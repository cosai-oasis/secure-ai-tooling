# Product → Component Lexicon (seed)

Maps common products/technologies to the CoSAI Risk Map component(s) they **implement or protect**. A **living seed** — extend it as products come up. When a product is not listed, infer the nearest component from its role (optionally confirm via web lookup) and **flag the mapping as inferred**, not curated.

Verify component ids against `risk-map/yaml/components.yaml` before relying on them — component ids evolve.

## Confidential / isolated compute infrastructure

| Product / technology | Component(s) it protects/implements | Note |
|---|---|---|
| AWS Nitro Enclaves, Azure Confidential Computing, GCP Confidential VMs, Intel SGX/TDX, AMD SEV, TEEs | `componentModelServing`, `componentModelStorage` | Confidential/isolated execution substrate for serving and stored artifacts; the relevant control is Isolated and Confidential Computing |

## Model serving / inference

| Product / technology | Component(s) | Note |
|---|---|---|
| vLLM, TGI (Text Generation Inference), NVIDIA Triton, Ray Serve, SageMaker/Vertex/Bedrock endpoints, KServe | `componentModelServing` | The runtime that serves predictions |
| Hosted model APIs (third-party model providers) | `componentTheModel`, `componentModelServing` | The model + its serving surface (you consume it) |

## Model & data storage / registries

| Product / technology | Component(s) | Note |
|---|---|---|
| Hugging Face Hub, MLflow Model Registry, model catalogs | `componentModelStorage` | Where model artifacts are stored/distributed |
| S3 / GCS / data lakes / feature stores (training data) | `componentDataStorage`, `componentTrainingData` | Training-data storage |

## Agent frameworks / orchestration

| Product / technology | Component(s) | Note |
|---|---|---|
| LangChain, LlamaIndex, Semantic Kernel, CrewAI, AutoGen, LangGraph | `componentReasoningCore`, `componentOrchestrationInputHandling`, `componentOrchestrationOutputHandling` | Agent reasoning + orchestration plumbing |
| MCP servers, tool servers, plugin hosts, remote tool endpoints | `componentTools` | The external tools an agent invokes (role-grain: tool server) |

## Retrieval / memory

| Product / technology | Component(s) | Note |
|---|---|---|
| Pinecone, Weaviate, Chroma, Milvus, pgvector (as a RAG corpus) | `componentRAGContent` | Retrieval-augmented content / vector store |
| Redis / a persistent agent memory store | `componentMemory` | Agent long-term/session memory |

## Input/output handling & guardrails

| Product / technology | Component(s) | Note |
|---|---|---|
| NeMo Guardrails, Llama Guard, prompt-filtering / content-moderation layers | `componentApplicationInputHandling`, `componentApplicationOutputHandling`, `componentAgentInputHandling`, `componentAgentOutputHandling` | Input/output validation loci (pick the layer that matches the deployment) |
| API gateways / auth proxies in front of AI services | `componentApplication` (+ the relevant input-handling component) | Application access boundary |

## Usage notes

- A product maps to the component(s) it **implements** (it *is* that locus) or **protects** (it secures that locus) — say which.
- Prefer the most specific component; a product may touch more than one.
- Not listed? Infer from role, confirm via web lookup if useful, and **flag the mapping as inferred**.
