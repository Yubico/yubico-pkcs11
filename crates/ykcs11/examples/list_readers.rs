/*
 * Copyright 2026 Yubico AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Run with: cargo run -p ykcs11 --example list_readers

fn main() {
    println!("Calling yubikit::platform::pcsc::list_readers_with_state() ...");
    match yubikit::platform::pcsc::list_readers_with_state() {
        Ok(readers) => {
            println!("Ok, {} reader(s):", readers.len());
            for (name, present) in readers {
                println!("  {name} (card present: {present})");
            }
        }
        Err(e) => {
            println!("Err: {e}");
        }
    }
    println!("Returned normally, no crash.");
}
