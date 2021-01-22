// mod xtea {
//     struct Context {
//         k: [u32;4],
//     }

//     /* 32-bit integer manipulation macros copied as is!!
//      */
//     pub fn get_uint32_be (b: [u32;16], i: usize) -> u32 {
//         b[i] << 24 | b[i+1] << 16 | b[i+2] << 8 | b[i+3]
//     }
//     fn put_uint32_be (n: u32, b: [u32;4], i: usize) {
//         b[i] = n >> 24;
//         b[i+1] = n >> 16;
//         b[i+2] = n >> 8;
//         b[i+3] = n;
//     }

//     fn init(ctx: Context) {
//         ctx.k.fill(0);
//     }

//     fn free(ctx: Option<Context>) {
//         match ctx {
//             None => {
//                 return;
//             },
//             Some(i) => {
//                 i.k.fill(0);
//                 ctx = None;
//                 return;
//             }
//         }
//     }

//     fn setup(ctx: Context, key: [u32;16]) {
//         let i = 0;
//         ctx.k.fill(0);

//         for i in 0..4 {
//             ctx.k[i] = get_uint32_be(key, i<<2);
//         }
//     }
// }

// #[cfg(test)]
// pub mod test {
//     fn test_get_uint32_be() {
        
//     }
// }
