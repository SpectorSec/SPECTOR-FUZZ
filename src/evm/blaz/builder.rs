use std::{
    collections::HashMap,
    fs,
    str::FromStr,
};

use bytes::Bytes;
use itertools::Itertools;
use libafl_bolts::impl_serdeany;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::error;

use crate::evm::{srcmap::SOURCE_MAP_PROVIDER, types::EVMAddress};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildJobResult {
    /// (file name, source code)
    pub sources: Vec<(String, String)>,
    pub source_maps: String,
    pub bytecodes: Bytes,
    pub abi: String,
    pub source_maps_replacements: Vec<(String, String)>,
    /// (file name, AST object)
    pub asts: Vec<(String, Value)>,
}

impl BuildJobResult {
    pub fn new(
        sources: Vec<(String, String)>,
        source_maps: String,
        bytecodes: Bytes,
        abi: String,
        replacements: Vec<(String, String)>,
        asts: Vec<(String, Value)>,
    ) -> Self {
        Self {
            sources,
            source_maps,
            bytecodes,
            abi,
            source_maps_replacements: replacements,
            asts,
        }
    }

    pub fn from_json(json: &Value) -> Option<Self> {
        let sourcemap = json["sourcemap"].as_str().expect("get sourcemap failed");
        let mut sourcemap_replacements = vec![];
        if let Some(_replaces) = json["replaces"].as_array() {
            sourcemap_replacements = _replaces
                .iter()
                .map(|v| {
                    let v = v.as_array().expect("get replace failed");
                    let source = v[0].as_str().expect("get source failed");
                    let target = v[1].as_str().expect("get target failed");
                    (source.to_string(), target.to_string())
                })
                .collect_vec();
        }
        let bytecode = json["runtime_bytecode"].as_str().expect("get bytecode failed");
        let source_objs = json["sources"].as_object().expect("get sources failed");
        let mut sources = vec![(String::new(), String::new()); source_objs.len()];
        for (k, v) in source_objs {
            let idx = match &v["id"] {
                Value::Number(v) => v.as_u64().unwrap() as usize,
                Value::String(v) => v.parse::<usize>().unwrap(),
                _ => {
                    error!("{:?} is not a valid source id", v["id"]);
                    return None;
                }
            };
            let code = v["source"].as_str().expect("get source code failed");
            sources[idx] = (k.clone(), code.to_string());
        }

        let abi = serde_json::to_string(&json["abi"]).expect("get abi failed");
        let ast_objs = json["ast"].as_object().expect("get ast failed");
        let asts: Vec<(String, Value)> = ast_objs.iter().map(|(k, v)| (k.clone(), v.clone())).collect();

        Some(Self {
            sources,
            source_maps: sourcemap.to_string(),
            bytecodes: Bytes::from(hex::decode(bytecode).unwrap_or_default()),
            abi: abi.to_string(),
            source_maps_replacements: sourcemap_replacements,
            asts,
        })
    }

    pub fn from_multi_file(file_path: String) -> HashMap<EVMAddress, Option<Self>> {
        let content = fs::read_to_string(file_path).expect("read file failed");
        let json = serde_json::from_str::<Value>(&content).expect("parse json failed");
        let json_arr = json.as_object().expect("get json array failed");
        let mut results = HashMap::new();
        for (k, v) in json_arr {
            let result = Self::from_json(v);
            let addr = EVMAddress::from_str(k).expect("parse address failed");
            results.insert(addr, result);
        }
        results
    }

    pub fn save_source_map(&self, address: &EVMAddress) {
        if SOURCE_MAP_PROVIDER.lock().unwrap().has_source_map(address) {
            return;
        }

        SOURCE_MAP_PROVIDER.lock().unwrap().decode_instructions_for_address(
            address,
            self.bytecodes.clone().to_vec(),
            self.source_maps.clone(),
            &self.sources,
            Some(&self.source_maps_replacements),
        );
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactInfoMetadata {
    pub info: HashMap<EVMAddress, BuildJobResult>,
}

impl Default for ArtifactInfoMetadata {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactInfoMetadata {
    pub fn new() -> Self {
        Self { info: HashMap::new() }
    }

    pub fn add(&mut self, addr: EVMAddress, result: BuildJobResult) {
        self.info.insert(addr, result);
    }

    pub fn get(&self, addr: &EVMAddress) -> Option<&BuildJobResult> {
        self.info.get(addr)
    }

    pub fn get_mut(&mut self, addr: &EVMAddress) -> Option<&mut BuildJobResult> {
        self.info.get_mut(addr)
    }
}

impl_serdeany!(ArtifactInfoMetadata);
