// ------------------------------------------------------------------------------
use crate::get_location_and_backtrace_on_panic;
use crate::vcp::VCPResult;
use crate::vcp::Error;
use crate::vcp::UnexpectedError;
// ------------------------------------------------------------------------------
use indexmap::IndexMap;
use std;
use std::backtrace::Backtrace;
use std::cell::Cell;
// ------------------------------------------------------------------------------

// for info on setting the panic hook see:
// https://users.rust-lang.org/t/pattern-for-extracting-panicinfo-during-catch-unwind/82069
//
// for getting the backtrace and putting it into a thread_local see:
// https://stackoverflow.com/questions/69593235/how-to-get-panic-information-i-e-stack-trace-with-catch-unwind/73711057#73711057

thread_local! {
    pub static BACKTRACE: Cell<Option<Backtrace>> = const { Cell::new(None) };
}

pub fn set_location_backtrace_hook() -> Box<dyn Fn(&std::panic::PanicHookInfo) + Send + Sync>
{
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|phi| {
        if let Some(location) = phi.location() {
            let to_file   = location.file();
            let to_line   = location.line();
            let to_col    = location.column();
            // the .caller method is in the doc, but not in code, so can't use it
            //let caller    = location.caller();
            // the next line just grabs the info of the actual line it is on, so not useful
            //let caller    = std::panic::Location::<'_>::caller();
            //let from_file = caller.file();
            //let from_line = caller.line();
            //let from_col  = caller.column();
            //let msg = format!("panic at {to_file}:{to_line}:{to_col} from {from_file}:{from_line}:{from_col}");
            // Note: this format enables editors (e.g., emacs) to go to
            // the indicated file at indicated line and column.
            let msg = format!("panic at {to_file}:{to_line}:{to_col}");
            // DO NOT COMMENT OUT THIS PRINTLN!
            // Otherwise no message will be printed to stderr on panic.
            println!("{msg}");
            let trace = Backtrace::force_capture();
            BACKTRACE.with(move |b| b.set(Some(trace)));
        };
    }));
    prev_hook
}

#[macro_export]
macro_rules! get_location_and_backtrace_on_panic {
    ($funcall:expr) => {
        {
            let prev_hook = set_location_backtrace_hook();

            let result = match std::panic::catch_unwind(|| $funcall)
            {
                Ok(o) => {
                    o
                },
                Err(e) => {
                    let backtrace = BACKTRACE.with(|b| b.take()).unwrap();
                    // Attempt to downcast to some known types.
                    // If none of the downcasts work, then print type info.
                    match e.downcast_ref::<String>()
                    {
                        Some(x) => {
                            Err(Error::UnexpectedError(UnexpectedError {
                                reason : x.to_string(),
                                backtrace,
                            }))
                        },
                        None => match e.downcast_ref::<i32>()
                        {
                            Some(x) => {
                                Err(Error::UnexpectedError(UnexpectedError {
                                    reason : format!("{x}"),
                                    backtrace,
                                }))
                            },
                            None => {
                                let id   = (*e).type_id();
                                let name = type_of(&*e);
                                Err(Error::UnexpectedError(UnexpectedError {
                                    reason : format!("{id:?} {name:?} {e:?}"),
                                    backtrace,
                                }))
                            }
                        }
                    }
                }
            };

            std::panic::set_hook(prev_hook);

            result

        }
    }
}

pub fn type_of<T>(_: T) -> &'static str {
    std::any::type_name::<T>()
}

