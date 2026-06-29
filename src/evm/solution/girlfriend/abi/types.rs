use std::fmt::Display;

use serde::Serialize;

#[derive(Debug, Serialize, Default, Clone, PartialEq, Eq)]
pub struct DecodedArg {
    pub ty: String,
    pub value: String,
    pub is_dynamic: bool,
}

#[derive(Debug, Serialize, Default, Clone, PartialEq, Eq)]
pub struct Bytes {
    pub var_name: String,
    pub selector: Option<String>,
    pub parts: Vec<DecodedArg>,
}

#[derive(Debug, Default, Serialize, Clone, PartialEq, Eq)]
pub struct StructDef {
    pub name: String,
    pub props: Vec<String>,
}

#[derive(Debug, Serialize, Default, Clone, PartialEq, Eq)]
pub struct StructIns {
    pub struct_name: String,
    pub var_name: String,
    pub values: Vec<DecodedArg>,
}

#[derive(Debug, Serialize, Default, Clone, PartialEq, Eq)]
pub struct Array {
    pub inner_type: String,
    pub len: Option<usize>,
    pub var_name: String,
    pub values: Vec<String>,
}

#[derive(Debug, Serialize, Default, Clone, PartialEq, Eq)]
pub enum MemoryVar {
    #[default]
    None,
    Bytes(Bytes),
    Array(Array),
    StructIns(StructIns),
}

impl DecodedArg {
    pub fn new(ty: &str, value: &str, is_dynamic: bool) -> Self {
        Self { ty: ty.to_string(), value: value.to_string(), is_dynamic }
    }
    pub fn replace_sender(&mut self, sender_var: &str) {
        if self.ty == "address" && self.value == sender_var {
            self.value = "tx.origin".to_string();
        }
    }
    pub fn replace_receiver(&mut self, receiver_var: &str) {
        if self.ty == "address" && self.value == receiver_var {
            self.value = "r".to_string();
        }
    }
}

impl Display for DecodedArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl Bytes {
    pub fn new(var_name: &str, selector: Option<String>, parts: &[DecodedArg]) -> Self {
        Self { var_name: var_name.to_string(), selector, parts: parts.to_vec() }
    }
    pub fn replace_sender(&mut self, sender_var: &str) {
        for part in &mut self.parts { part.replace_sender(sender_var); }
    }
    pub fn replace_receiver(&mut self, receiver_var: &str) {
        for part in &mut self.parts { part.replace_receiver(receiver_var); }
    }
    pub fn value(&self) -> String {
        match &self.selector {
            Some(s) => {
                if self.parts.is_empty() {
                    format!("abi.encodeWithSelector({})", s)
                } else {
                    let args: Vec<_> = self.parts.iter().map(|p| p.to_string()).collect();
                    format!("abi.encodeWithSelector({}, {})", s, args.join(", "))
                }
            }
            None => {
                if self.parts.is_empty() { "\"\"".to_string() }
                else if self.parts.len() == 1 && self.parts[0].ty == "bytes" { self.parts[0].to_string() }
                else {
                    let args: Vec<_> = self.parts.iter().map(|p| p.to_string()).collect();
                    format!("abi.encode({})", args.join(", "))
                }
            }
        }
    }
}

impl Display for Bytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "bytes memory {} = {};", self.var_name, self.value())
    }
}

impl StructDef {
    pub fn new(name: &str, props: &[String]) -> Self {
        Self { name: name.to_string(), props: props.to_vec() }
    }
}

impl StructIns {
    pub fn new(struct_name: &str, var_name: &str, values: &[DecodedArg]) -> Self {
        Self { struct_name: struct_name.to_string(), var_name: var_name.to_string(), values: values.to_vec() }
    }
    pub fn replace_sender(&mut self, sender_var: &str) {
        for value in &mut self.values { value.replace_sender(sender_var); }
    }
    pub fn replace_receiver(&mut self, receiver_var: &str) {
        for value in &mut self.values { value.replace_receiver(receiver_var); }
    }
    pub fn value(&self) -> String {
        let args: Vec<_> = self.values.iter().map(|p| p.to_string()).collect();
        format!("{}({})", self.struct_name, args.join(", "))
    }
}

impl Display for StructIns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} memory {} = {};", self.struct_name, self.var_name, self.value())
    }
}

impl Array {
    pub fn new(inner_type: &str, len: Option<usize>, var_name: &str, values: &[String]) -> Self {
        Self { inner_type: inner_type.to_string(), len, var_name: var_name.to_string(), values: values.to_vec() }
    }
    pub fn replace_sender(&mut self, sender_var: &str) {
        if self.inner_type == "address" {
            for value in &mut self.values {
                if value == sender_var { *value = "tx.origin".to_string(); }
            }
        }
    }
    pub fn replace_receiver(&mut self, receiver_var: &str) {
        if self.inner_type == "address" {
            for value in &mut self.values {
                if value == receiver_var { *value = "r".to_string(); }
            }
        }
    }
    pub fn generate_sol_code(&self) -> Vec<String> {
        let mut code = vec![];
        if let Some(len) = self.len {
            code.push(format!("{}[{}] memory {};", self.inner_type, len, self.var_name));
        } else {
            code.push(format!("{}[] memory {} = new {}[]({});", self.inner_type, self.var_name, self.inner_type, self.values.len()));
        }
        for (i, value) in self.values.iter().enumerate() {
            code.push(format!("{}[{}] = {};", self.var_name, i, value));
        }
        code
    }
    pub fn value(&self) -> String {
        format!("new {}[]({})", self.inner_type, self.values.join(", "))
    }
}

impl MemoryVar {
    pub fn replace_sender(&mut self, sender_var: &str) {
        match self {
            MemoryVar::Bytes(b) => b.replace_sender(sender_var),
            MemoryVar::Array(a) => a.replace_sender(sender_var),
            MemoryVar::StructIns(s) => s.replace_sender(sender_var),
            _ => {}
        }
    }
    pub fn replace_receiver(&mut self, receiver_var: &str) {
        match self {
            MemoryVar::Bytes(b) => b.replace_receiver(receiver_var),
            MemoryVar::Array(a) => a.replace_receiver(receiver_var),
            MemoryVar::StructIns(s) => s.replace_receiver(receiver_var),
            _ => {}
        }
    }
    pub fn generate_sol_code(&self) -> Vec<String> {
        match self {
            MemoryVar::Bytes(b) => vec![b.to_string()],
            MemoryVar::Array(a) => a.generate_sol_code(),
            MemoryVar::StructIns(s) => vec![s.to_string()],
            _ => vec![],
        }
    }
    pub fn into_bytes(self) -> Option<Bytes> {
        match self { MemoryVar::Bytes(b) => Some(b), _ => None }
    }
    pub fn var_name(&self) -> Option<String> {
        match self {
            MemoryVar::Bytes(b) => Some(b.var_name.clone()),
            MemoryVar::Array(a) => Some(a.var_name.clone()),
            MemoryVar::StructIns(s) => Some(s.var_name.clone()),
            _ => None,
        }
    }
    pub fn value(&self) -> Option<String> {
        match self {
            MemoryVar::Bytes(b) => Some(b.value()),
            MemoryVar::Array(a) => Some(a.value()),
            MemoryVar::StructIns(s) => Some(s.value()),
            _ => None,
        }
    }
}
