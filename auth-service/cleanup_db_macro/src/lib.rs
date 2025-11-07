use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn, parse::Parse, parse::ParseStream, Ident, Stmt, parse_quote};

struct CleanupArgs {
    var_name: Ident,
}

impl Parse for CleanupArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let var_name: Ident = input.parse()?;
        Ok(CleanupArgs { var_name })
    }
}

#[proc_macro_attribute]
pub fn with_cleanup(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as CleanupArgs);
    let var_name = args.var_name;

    let mut function = parse_macro_input!(item as ItemFn);

    // Add cleanup call as the last statement
    let cleanup_call: Stmt = parse_quote! {
        #var_name.cleanup().await;
    };

    function.block.stmts.push(cleanup_call);

    TokenStream::from(quote! {
        #function
    })
}