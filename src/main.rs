#![feature(btree_range, collections_bound)]
extern crate regex;

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::fmt;
use std::fmt::Display;
use std::fs::File;
use std::path::Path;
use regex::Regex;

struct Symbol {
    name: String,
    module: Option<String>,
}

impl Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(ref m) = self.module {
            write!(f, "{}[{}]", self.name, m)
        } else {
            write!(f, "{}", self.name)
        }
    }
}

fn kallsyms<F: BufRead>(f: F) -> BTreeMap<u64, Symbol> {
    let regex = r"(?x)
        (?P<addr>[0-9a-fA-F]+)\s    # Address
        (?P<type>[:alpha:])\s       # Type
        (?P<name>\S+)               # Name
        (?:\s+\[(?P<mod>\S+)\])?    # Optional module
        ";
    let regex = Regex::new(regex).unwrap();
    f.lines().map(|line| {
        let line = line.unwrap();
        if let Some(caps) = regex.captures(&line) {
            let addr = caps.name("addr").unwrap();
            let addr = u64::from_str_radix(addr, 16).expect("Failed to parse address");
            let name = caps.name("name").unwrap().to_string();
            let module = caps.name("mod").map(|x| x.to_string());
            (addr, Symbol {
                name: name,
                module: module,
            })
        } else {
            panic!("Symbol line not matched: {}", line);
        }
    }).collect()
}

type Syms = BTreeMap<u64, Symbol>;

struct SymOffset<'a> {
    addr: u64,
    offset: u64,
    sym: &'a Symbol,
}

impl<'a> Display for SymOffset<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.offset > 0 {
            write!(f, "{}+0x{:x}", self.sym, self.offset)
        } else {
            write!(f, "{}", self.sym)
        }
    }
}

fn find_sym(needle: u64, syms: &Syms) -> Option<SymOffset> {
    use std::collections::Bound;
    // Most efficient way (I can find as of Rust 1.11) to search for the
    // closest <= element. range() internally finds the first and last nodes
    // immediately. next_back() of the DoubleEndedIterator returns the last
    // node directly. Avoid last() on the Iterator because it uses the default
    // implementation that iterates sequentially and takes ~10 seconds for the
    // whole file.
    //
    // Unbounded range on the left still traverses to the left-most node which
    // is technically unnecessary work.
    syms.range(Bound::Unbounded, Bound::Included(&needle)).next_back()
        .map(|(addr, sym)| (SymOffset { addr: *addr, offset: needle - addr, sym: sym }))
}

struct FnCall {
    cpu: u32,
    from: u64,
    to: u64,
}

fn ftrace<F: BufRead>(f: F) -> Vec<FnCall> {
    let regex = r"(?x)
        (?P<cpu>\d+)\s+             # CPU
        (?P<to>[0-9a-fA-F]+)\s+     # To Addr
        (?P<from>[0-9a-fA-F]+)\s+   # From Addr
        ";
    let regex = Regex::new(regex).unwrap();
    f.lines().map(|line| {
        let line = line.unwrap();
        let caps = regex.captures(&line).expect("Failed to match ftrace line");
        let s_cpu = caps.name("cpu").unwrap();
        let cpu = u32::from_str_radix(s_cpu, 10).expect("Failed to parse CPU");
        let s_from = caps.name("from").unwrap();
        let from = u64::from_str_radix(s_from, 16).expect("Failed to parse address");
        let s_to = caps.name("to").unwrap();
        let to = u64::from_str_radix(s_to, 16).expect("Failed to parse address");
        FnCall {
            cpu: cpu,
            from: from,
            to: to,
        }
    }).collect()
}

fn read_kallsyms<P: AsRef<Path> + Display>(path: P) -> Syms {
    println!("Reading kallsyms from {}", path);
    let f = File::open(path).unwrap();
    let reader = BufReader::new(f);

    // Read kallsyms
    kallsyms(reader)
}

fn read_ftrace<P: AsRef<Path> + Display>(path: P) -> Vec<FnCall> {
    println!("Reading ftrace from {}", path);
    let f = File::open(path).unwrap();
    let reader = BufReader::new(f);

    // Read ftrace
    ftrace(reader)
}

fn main() {
    let tracefile = std::env::args().nth(2).expect("Second argument must be pstore ftrace output");
    let calls = read_ftrace(tracefile);
    let symsfile = std::env::args().nth(1).expect("First argument must be kallsyms");
    let syms = read_kallsyms(symsfile);

    // Search
    for call in calls {
        let from = find_sym(call.from, &syms).unwrap();
        let to = find_sym(call.to, &syms).unwrap();
        println!("{} {} <- {}", call.cpu, to.sym, from);
    }
}
