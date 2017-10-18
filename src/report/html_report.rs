use std::collections::HashSet;
use std::fs::File;
use std::path::Path;
use std::io::prelude::*;

use horrorshow::RenderBox;
use horrorshow::helper::doctype;
use horrorshow::prelude::*;

use config::Config;
use traces::TraceMap;


#[derive(Eq, PartialEq, Clone, Copy, Ord, PartialOrd, Hash)]
struct CoverageRow<'a> {
    path: &'a Path,
    depth: usize,
    line_coverage: usize,
    hit_rate: usize,
}

fn get_entries(res:&TraceMap) -> Vec<CoverageRow> {
    vec![]
}


fn render_results(res: &TraceMap) -> Box<RenderBox> {
    if res.is_empty() {
        box_html! {
            p {
                :"No coverage results to show"
            }
        }
    } else {
        box_html! {
            table(class="table table-striped") {
                thead {
                    tr {
                        th { :"Item" }
                        th { :"Line Coverage" }
                        th { :"Hit Rate" }
                    }
                }
                tbody {
                    @ for r in get_entries(res){
                        tr {
                            td{:r.path.display()}
                            td{:format!("{}%", r.line_coverage)}
                            td{:format!("{}", r.hit_rate)}
                        }
                    }
                }
            }
        }
    }
}

pub fn export(coverage_data: &TraceMap, config: &Config) {
    let report = html! {
        :doctype::HTML;
        html {
            head {
                title: "Tarpaulin Coverage Report";
                p {
                    :Raw(r#"<!-- Latest compiled and minified CSS -->
                    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" 
                    integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" 
                    crossorigin="anonymous">

                    <!-- Optional theme -->
                    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap-theme.min.css" 
                    integrity="sha384-rHyoN1iRsVXV4nD0JutlnGaslCJuC7uwjduW9SVrLvRYooPp2bWYgmgJQIXwl/Sp" 
                    crossorigin="anonymous">

                    <!-- Latest compiled and minified JavaScript -->
                    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js" 
                    integrity="sha384-Tc5IQib027qvyjSMfHjOMaLkfuWVxZxUPnCJA7l2mCWNIpG9mGCD8wGNIcPD7Txa" 
                    crossorigin="anonymous"></script>"#)
                }
            }
            body {
                div(class="container") {
                    div(class="page-header") {
                        h1 {
                            :"Tarpaulin Coverage Report"
                        }
                    }
                    h3 {
                        :"Run Summary"
                    }
                    p {
                        :format!("Manifest path {}", config.manifest.display()) 
                    }
                    h3 {
                        :"Coverage Results"
                    }
                    p {
                        : render_results(coverage_data)
                    }
                }
            }
        }
    }.into_string().unwrap();

    let mut file = match File::create("tarpaulin.html") {
        Err(e) => {
            println!("Failed to export report {}", e);
            return;
        },
        Ok(file) => file,
    };
    let _ = file.write_all(report.as_bytes());
}
