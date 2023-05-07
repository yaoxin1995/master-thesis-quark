// Copyright (c) 2021 Quark Container Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{result::Result as SResult, sync::atomic::AtomicI64};
use std::sync::Arc;
use qobjs::pb_gen::node_mgr_pb::node_agent_stream_msg::EventBody;
use tonic::Status;
use qobjs::pb_gen::node_mgr_pb::{self as nm_svc, NodeRegister};
use tokio::sync::mpsc;
use core::ops::Deref;
use k8s_openapi::api::core::v1 as k8s;

use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Mutex;

use tokio::sync::Notify;
use tonic::Streaming;
use tokio::sync::oneshot;

use qobjs::pb_gen::node_mgr_pb as NmMsg;
use qobjs::common::*;

use crate::nm_svc::NodeMgrSvc;


#[derive(Debug)]
pub struct NodeAgentInner {
    pub sender: mpsc::Sender<SResult<nm_svc::NodeAgentMessage, Status>>,
    pub revision: AtomicI64,
}

#[derive(Clone, Debug)]
pub struct NodeAgent(Arc<NodeAgentInner>);

impl Deref for NodeAgent {
    type Target = Arc<NodeAgentInner>;

    fn deref(&self) -> &Arc<NodeAgentInner> {
        &self.0
    }
}

impl NodeAgent {
    //pub fn New()

    pub async fn Send(&self, msg: nm_svc::NodeAgentMessage) -> Result<()>{
        match self.sender.send(Ok(msg)).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                return Err(Error::CommonError(format!("NodeAgent Send error {:?}", e)));
            }
        }
    }


}

#[derive(Debug)]
pub struct QClientInner {
    pub closeNotify: Arc<Notify>,
    pub stop: AtomicBool,

    pub nodeMgrSvc: NodeMgrSvc,
    pub nodeName: Mutex<String>,
    pub uid: Mutex<String>,

    pub rx: Mutex<Option<Streaming<NmMsg::NodeAgentRespMsg>>>,
    pub tx: mpsc::Sender<SResult<NmMsg::NodeAgentReq, Status>>,
    pub pendingReqs: Mutex<BTreeMap<u64, oneshot::Sender<NmMsg::NodeAgentResp>>>,
    pub nextReqId: AtomicU64,
}

#[derive(Debug, Clone)]
pub struct QClient(Arc<QClientInner>);

impl Deref for QClient {
    type Target = Arc<QClientInner>;

    fn deref(&self) -> &Arc<QClientInner> {
        &self.0
    }
}

impl QClient {
    pub fn New(svc: &NodeMgrSvc, rx: Streaming<NmMsg::NodeAgentRespMsg>, tx: mpsc::Sender<SResult<NmMsg::NodeAgentReq, Status>>) -> Self {
        let inner = QClientInner {
            closeNotify: Arc::new(Notify::new()),
            stop: AtomicBool::new(false),
            nodeMgrSvc: svc.clone(),
            nodeName: Mutex::new(String::new()),
            uid: Mutex::new(String::new()),
            rx: Mutex::new(Some(rx)),
            tx: tx,
            pendingReqs: Mutex::new(BTreeMap::new()),
            nextReqId: AtomicU64::new(1),
        };

        return Self(Arc::new(inner));
    }

    pub async fn Process(&self) {
        match self.ProcessInner().await {
            Err(e) => error!("QClient get error {:?}", e),
            Ok(()) => (),
        }

        let nodename = self.nodeName.lock().unwrap().clone();
        if nodename.len() != 0 {
            self.nodeMgrSvc.clients.lock().unwrap().remove(&nodename);
        }
    }

    pub async fn ProcessInner(&self) -> Result<()> {
        let mut rx = self.rx.lock().unwrap().take().unwrap();
        loop {
            tokio::select! {
                _ = self.closeNotify.notified() => {
                    self.stop.store(false, Ordering::SeqCst);
                    break;
                }
                msg = rx.message() => {
                    match msg {
                        Err(e) => return Err(Error::CommonError(format!("QClient::Process rx message fail {:?}", e))),
                        Ok(msg) => {
                            match msg {
                                None => break,
                                Some(msg) => {
                                    match msg.message_body.unwrap() {
                                        NmMsg::node_agent_resp_msg::MessageBody::NodeAgentResp(resp) => {
                                            let reqId = resp.request_id;
                                            let chann = self.pendingReqs.lock().unwrap().remove(&reqId);
                                            match chann {
                                                None => error!("QClient::Process get none exist response {:?}", resp),
                                                Some(chann) => {
                                                    match chann.send(resp) {
                                                        Ok(()) => (),
                                                        Err(e) => {
                                                            error!("QClient::Process send messaage fail response {:?}", e);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        NmMsg::node_agent_resp_msg::MessageBody::NodeAgentStreamMsg(msg) => {
                                            self.ProcessStreamMsg(msg).await?;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        return Ok(())
    }

    pub async fn ProcessStreamMsg(&self, msg: NmMsg::NodeAgentStreamMsg) -> Result<()> {
        let event: NmMsg::node_agent_stream_msg::EventBody = msg.event_body.unwrap();
        match event {
            EventBody::NodeRegister(msg) => {
                return self.OnNodeRegister(msg).await;
            }
            _ => {
                unimplemented!()
            }
        }
    }

    pub async fn OnNodeRegister(&self, msg: NodeRegister) -> Result<()> {
        assert!(self.nodeName.lock().unwrap().len() == 0); // hasn't got the register message before
        let node : k8s::Node = serde_json::from_str(&msg.node)?;
        let name = node.metadata.name.as_deref().unwrap_or("").to_string();
        let uid = node.metadata.uid.as_deref().unwrap_or("").to_string();
        *self.nodeName.lock().unwrap() = name.clone();
        *self.uid.lock().unwrap() = uid.clone();

        self.nodeMgrSvc.clients.lock().unwrap().insert(name, self.clone());

        let req = NmMsg::NodeConfigReq {
            cluster_domain: "".to_string(),
            node: serde_json::to_string(&k8s::Node::default())?,
        };

        match self.Call(NmMsg::node_agent_req::MessageBody::NodeConfigReq(req)).await {
            Err(e) => {
                // todo: handle the failure
                error!("OnNodeRegister get error {:?}", e);
            }
            Ok(_) => (),
        };

        return Ok(())
    }

    pub fn ReqId(&self) -> u64 {
        return self.nextReqId.fetch_add(1, Ordering::Release) + 1;
    }

    pub async fn Call(&self, req: NmMsg::node_agent_req::MessageBody) -> Result<NmMsg::node_agent_resp::MessageBody> {
        let reqId = self.ReqId();
        let req = NmMsg::NodeAgentReq {
            request_id: reqId,
            message_body: Some(req),
        };
        let (tx, rx) = oneshot::channel::<NmMsg::NodeAgentResp>();

        self.pendingReqs.lock().unwrap().insert(reqId, tx);
        match self.tx.send(Ok(req)).await {
            Ok(()) => (),
            Err(e) => {
                return Err(Error::CommonError(format!("QClient::Call send fail with error {:?}", e)));
            }
        }
        
        let resp = match rx.await {
            Ok(r) => r,
            Err(e) => return Err(Error::CommonError(format!("QClient::Call recv fail with error {:?}", e))),
        };

        if resp.error.len() != 0 {
            return Err(Error::CommonError(resp.error));
        }

        return Ok(resp.message_body.unwrap());
    }
}