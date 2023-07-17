use actix::AsyncContext;
use actix::{Actor, StreamHandler};
use actix_files::NamedFile;
use actix_web::{
    http::header::{HeaderValue, CONTENT_DISPOSITION, CONTENT_TYPE},
    web, App, Error as AError, HttpRequest, HttpResponse, HttpServer,
};
use actix_web_actors::ws;
use clap::{Parser as ClapParser, Subcommand};
use html_editor::operation::*;
use html_editor::{parse, Node};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::time::Duration;
use swc_atoms::js_word;
use swc_bundler::{Bundle, Bundler, Load, ModuleData, ModuleRecord};
use swc_common::{
    self,
    comments::SingleThreadedComments,
    errors::{ColorConfig, Handler},
    sync::Lrc,
    FileName, FilePathMapping, Globals, Mark, SourceMap, Span, GLOBALS,
};
use swc_ecma_ast::*;
use swc_ecma_codegen::{
    text_writer::{omit_trailing_semi, JsWriter, WriteJs},
    Emitter,
};
use swc_ecma_loader::{
    resolvers::{lru::CachingResolver, node::NodeModulesResolver},
    TargetEnv,
};
use swc_ecma_parser::{lexer::Lexer, parse_file_as_module, Parser, StringInput, Syntax, TsConfig};
use swc_ecma_transforms_base::{fixer::fixer, hygiene::hygiene, resolver};
use swc_ecma_transforms_typescript::strip;
use swc_ecma_visit::FoldWith;
use tempfile::NamedTempFile;

fn print_bundles(cm: Lrc<SourceMap>, modules: Vec<Bundle>, minify: bool) {
    for bundled in modules {
        let code = {
            let mut buf = vec![];

            {
                let wr = JsWriter::new(cm.clone(), "\n", &mut buf, None);
                let mut emitter = Emitter {
                    cfg: swc_ecma_codegen::Config {
                        minify,
                        ..Default::default()
                    },
                    cm: cm.clone(),
                    comments: None,
                    wr: if minify {
                        Box::new(omit_trailing_semi(wr)) as Box<dyn WriteJs>
                    } else {
                        Box::new(wr) as Box<dyn WriteJs>
                    },
                };
                let globals = Globals::default();
                GLOBALS.set(&globals, || {
                    let unresolved_mark = Mark::new();
                    let top_level_mark = Mark::new();

                    let module = bundled.module;
                    let module =
                        module.fold_with(&mut resolver(unresolved_mark, top_level_mark, true));
                    let module = module.fold_with(&mut strip(top_level_mark));
                    let module = module.fold_with(&mut hygiene());

                    emitter.emit_module(&module).unwrap();
                });
            }

            String::from_utf8_lossy(&buf).to_string()
        };

        println!("Created output.js ({}kb)", code.len() / 1024);
        std::fs::write("./dist/output.js", &code).unwrap();
    }
}

struct Hook;

impl swc_bundler::Hook for Hook {
    fn get_import_meta_props(
        &self,
        span: Span,
        module_record: &ModuleRecord,
    ) -> Result<Vec<KeyValueProp>, anyhow::Error> {
        let file_name = module_record.file_name.to_string();

        Ok(vec![
            KeyValueProp {
                key: PropName::Ident(Ident::new(js_word!("url"), span)),
                value: Box::new(Expr::Lit(Lit::Str(Str {
                    span,
                    raw: None,
                    value: file_name.into(),
                }))),
            },
            KeyValueProp {
                key: PropName::Ident(Ident::new(js_word!("main"), span)),
                value: Box::new(if module_record.is_entry {
                    Expr::Member(MemberExpr {
                        span,
                        obj: Box::new(Expr::MetaProp(MetaPropExpr {
                            span,
                            kind: MetaPropKind::ImportMeta,
                        })),
                        prop: MemberProp::Ident(Ident::new(js_word!("main"), span)),
                    })
                } else {
                    Expr::Lit(Lit::Bool(Bool { span, value: false }))
                }),
            },
        ])
    }
}

fn do_bundle(
    _entry: &Path,
    entries: std::collections::HashMap<String, FileName>,
    inline: bool,
    minify: bool,
) {
    let globals = Box::leak(Box::default());
    let cm = Lrc::new(SourceMap::new(FilePathMapping::empty()));

    let mut bundler = Bundler::new(
        globals,
        cm.clone(),
        Loader { cm: cm.clone() },
        CachingResolver::new(
            4096,
            NodeModulesResolver::new(TargetEnv::Node, Default::default(), true),
        ),
        swc_bundler::Config {
            require: true,
            disable_inliner: !inline,
            external_modules: Default::default(),
            //disable_fixer: minify,
            //disable_hygiene: minify,
            //disable_dce: true,
            module: Default::default(),
            ..Default::default()
        },
        Box::new(Hook),
    );
    let modules = bundler
        .bundle(entries)
        .map_err(|err| println!("{:?}", err))
        .unwrap();
    println!("Bundled as {} modules", modules.len());
    {
        let cm = cm;
        print_bundles(cm, modules, minify);
    }
}

pub struct Loader {
    pub cm: Lrc<SourceMap>,
}

impl Load for Loader {
    fn load(&self, f: &FileName) -> Result<ModuleData, anyhow::Error> {
        let fm = match f {
            FileName::Real(path) => self.cm.load_file(path)?,
            _ => unreachable!(),
        };

        let module = parse_file_as_module(
            &fm,
            Syntax::Typescript(TsConfig {
                ..Default::default()
            }),
            EsVersion::Es2020,
            None,
            &mut vec![],
        )
        .unwrap_or_else(|err| {
            let handler =
                Handler::with_tty_emitter(ColorConfig::Always, false, false, Some(self.cm.clone()));
            err.into_diagnostic(&handler).emit();
            panic!("failed to parse")
        });

        Ok(ModuleData {
            fm,
            module,
            helpers: Default::default(),
        })
    }
}

#[derive(Debug, ClapParser)]
#[clap(name = "subcommand", version)]
struct Args {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Dev,
    Build,
}

async fn index(req: HttpRequest) -> HttpResponse {
    let virtual_script_id = "@mvite:reload/script.js";
    let virtual_script = "
        const ws = new WebSocket('ws://localhost:8080/ws')
        ws.addEventListener('message', ({ data }) => {
        const msg = JSON.parse(data)
        if (msg.type === 'reload') {
            location.reload()
        }
        })
    ";
    let mut path: PathBuf = req.clone().match_info().query("filename").parse().unwrap();
    let ext_opt = path.extension();
    let mut ext = std::ffi::OsStr::new("");
    if ext_opt == None {
        for e in ["", "js", "ts"] {
            let mut path2 = path.clone();
            if e != "" {
                path2.set_extension(e);
            }
            if path2.exists() {
                ext = std::ffi::OsStr::new(e);
                path = path2;
                break;
            }
        }
    } else {
        ext = ext_opt.unwrap();
    }
    if ext == "html" {
        let file_content = std::fs::read_to_string(&path).unwrap();
        let mut dom = parse(&file_content).unwrap();
        dom.insert_to(
            &Selector::from("head"),
            Node::new_element(
                "script",
                vec![("type", "module"), ("src", virtual_script_id)],
                vec![],
            ),
        );
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "{}", dom.trim().html());
        let mut res = NamedFile::open(file.path()).unwrap().into_response(&req);
        res.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
        res.headers_mut().insert(
            CONTENT_DISPOSITION,
            HeaderValue::from_static("inline; filename=\"index.html\""),
        );
        return res;
    }
    if ext == "ts" {
        let transpiled = transpile(&path.as_path().to_str().unwrap());
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "{}", transpiled);
        let mut res = NamedFile::open(file.path()).unwrap().into_response(&req);
        res.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/javascript"),
        );
        return res;
    }
    if ext == "js" {
        if path.as_path().to_str().unwrap() == virtual_script_id {
            let mut file = NamedTempFile::new().unwrap();
            writeln!(file, "{}", virtual_script);
            let mut res = NamedFile::open(file.path()).unwrap().into_response(&req);
            res.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_static("application/javascript"),
            );
            return res;
        }
        let mut res = NamedFile::open(path).unwrap().into_response(&req);
        res.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/javascript"),
        );
        return res;
    }
    NamedFile::open(path).unwrap().into_response(&req)
}

#[actix_web::main]
async fn start_dev() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    log::info!("dev server running at http://localhost:8080");
    HttpServer::new(|| {
        App::new()
            .route("/ws", web::get().to(ws_index))
            .route("/{filename:.*}", web::get().to(index))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

fn transpile(input: &str) -> String {
    let cm: Lrc<SourceMap> = Default::default();
    let handler = Handler::with_tty_emitter(ColorConfig::Auto, true, false, Some(cm.clone()));

    let fm = cm
        .load_file(Path::new(&input))
        .expect("failed to load input typescript file");

    let comments = SingleThreadedComments::default();

    let lexer = Lexer::new(
        Syntax::Typescript(TsConfig {
            tsx: input.ends_with(".tsx"),
            ..Default::default()
        }),
        Default::default(),
        StringInput::from(&*fm),
        Some(&comments),
    );

    let mut parser = Parser::new_from(lexer);

    for e in parser.take_errors() {
        e.into_diagnostic(&handler).emit();
    }

    let module = parser
        .parse_module()
        .map_err(|e| e.into_diagnostic(&handler).emit())
        .expect("failed to parse module.");

    let globals = Globals::default();
    let mut ret = String::new();
    GLOBALS.set(&globals, || {
        let unresolved_mark = Mark::new();
        let top_level_mark = Mark::new();

        let module = module.fold_with(&mut resolver(unresolved_mark, top_level_mark, true));
        let module = module.fold_with(&mut strip(top_level_mark));
        let module = module.fold_with(&mut hygiene());
        let module = module.fold_with(&mut fixer(Some(&comments)));

        let mut buf = vec![];
        {
            let mut emitter = Emitter {
                cfg: swc_ecma_codegen::Config {
                    minify: false,
                    ..Default::default()
                },
                cm: cm.clone(),
                comments: Some(&comments),
                wr: JsWriter::new(cm.clone(), "\n", &mut buf, None),
            };

            emitter.emit_module(&module).unwrap();
        }
        ret = String::from_utf8(buf).unwrap();
    });
    ret
}

struct MviteWs;

impl Actor for MviteWs {
    type Context = ws::WebsocketContext<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.run_later(Duration::from_secs(5), |_, ctx| {
            let (sender, receiver) = channel();
            let mut watcher: RecommendedWatcher = Watcher::new(
                sender,
                notify::Config::default().with_poll_interval(Duration::from_secs(2)),
            )
            .unwrap();
            watcher
                .watch(std::path::Path::new("."), RecursiveMode::Recursive)
                .unwrap();
            loop {
                match receiver.recv() {
                    Ok(_) => {
                        println!("Received");
                        ctx.text("{\"type\": \"reload\"}");
                        break;
                    }
                    Err(e) => println!("watch error: {:?}", e),
                }
            }
        });
    }
}

impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for MviteWs {
    fn handle(&mut self, msg: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
        match msg {
            Ok(ws::Message::Ping(msg)) => ctx.pong(&msg),
            Ok(ws::Message::Text(text)) => ctx.text(text),
            Ok(ws::Message::Binary(bin)) => ctx.binary(bin),
            _ => (),
        }
    }
}

async fn ws_index(req: HttpRequest, stream: web::Payload) -> Result<HttpResponse, AError> {
    let resp = ws::start(MviteWs {}, &req, stream);
    resp
}

fn start_build() {
    let dist_dir_name = "./dist";
    let dist_dir = std::path::Path::new(dist_dir_name);
    if dist_dir.exists() && dist_dir.is_dir() {
        let _ = std::fs::remove_dir_all(dist_dir_name);
    }
    let _ = std::fs::create_dir(dist_dir);
    let index_html_path = "./index.html";
    let dist_html_path = "./dist/index.html";
    process_html(index_html_path, dist_html_path);
}

fn bundle_entrypoint(path: &str) -> String {
    let mut entries = std::collections::HashMap::default();
    entries.insert("main".to_string(), FileName::Real(path.clone().into()));

    do_bundle(Path::new(path), entries, false, false);
    "/output.js".to_owned()
}

fn process_html(html_path: &str, dist_html_path: &str) {
    let file_content = std::fs::read_to_string(html_path).unwrap();
    let mut dom = parse(&file_content).unwrap();
    let selector: Selector = Selector::from("script");
    let script = dom.query(&selector).unwrap();

    let attr = &script.attrs[0];
    let src = &attr.1;
    let new_src = bundle_entrypoint(&format!(".{}", src));
    dom.execute_for(&selector, |elem| {
        elem.attrs.clear();
        elem.attrs.push(("src".to_string(), new_src.clone()));
    });
    let mut file = std::fs::File::create(dist_html_path).unwrap();
    writeln!(file, "{}", dom.trim().html());
}

fn main() {
    let args = Args::parse();
    match args.command {
        Commands::Dev => {
            let _ = start_dev();
        }
        Commands::Build => start_build(),
    }
}
