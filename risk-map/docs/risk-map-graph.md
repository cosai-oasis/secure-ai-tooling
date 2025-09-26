```mermaid
---
config:
  layout: elk
  elk:
    mergeEdges: False
    nodePlacementStrategy: BRANDES_KOEPF
---

graph TD
   %%{init: {'flowchart': {'nodeSpacing': 25, 'rankSpacing': 30, 'padding': 5, 'wrappingWidth': 250}}}%%
    classDef hidden display: none;
    classDef allControl stroke:#4285f4,stroke-width:2px,stroke-dasharray: 5 5

    subgraph componentsInfrastructure ["Infrastructure Components"]
        componentDataStorage[Data Storage Infrastructure]
        componentModelServing[Model Serving Infrastructure]
        componentModelStorage[Model Storage]
        subgraph componentsData ["Data"]
            componentDataFilteringAndProcessing[Data Filtering and Processing]
            componentDataSources[Data Sources]
            componentTrainingData[Training Data]
        end
    end

    subgraph componentsModel ["Model Components"]
        componentTheModel[The Model]
        subgraph componentsModelTraining ["Model Training"]
            componentModelEvaluation[Model Evaluation]
            componentModelFrameworksAndCode[Model Frameworks and Code]
            componentModelTrainingTuning[Training and Tuning]
        end
        subgraph componentsOrchestration ["Orchestration"]
            componentMemory[Model Memory]
            componentOrchestrationInputHandling[Input Handling]
            componentOrchestrationOutputHandling[Output Handling]
            componentRAGContent[Retrieval Augmented Generation & Content]
            componentTools[External Tools and Services]
        end
    end

    subgraph componentsApplication ["Application Components"]
        componentApplication[Application]
        componentApplicationInputHandling[Input Handling]
        componentApplicationOutputHandling[Output Handling]
        subgraph componentsAgent ["Agent"]
            componentAgentInputHandling[Input Handling]
            componentAgentOutputHandling[Output Handling]
            componentAgentSystemInstruction[Agent System Instructions]
            componentAgentUserQuery[Agent User Query]
            componentReasoningCore[Agent Reasoning Core]
        end
    end


    componentDataSources --> componentDataFilteringAndProcessing
    componentDataFilteringAndProcessing --> componentTrainingData
    componentTrainingData --> componentDataStorage
    componentDataStorage --> componentModelTrainingTuning
    componentModelFrameworksAndCode --> componentModelTrainingTuning
    componentModelEvaluation --> componentModelTrainingTuning
    componentModelTrainingTuning --> componentTheModel
    componentModelStorage --> componentTheModel
    componentModelServing --> componentTheModel
    componentTheModel --> componentModelEvaluation
    componentTheModel --> componentAgentInputHandling
    componentTheModel --> componentApplicationInputHandling
    componentTheModel --> componentOrchestrationInputHandling
    componentApplication --> componentApplicationOutputHandling
    componentApplication --> componentAgentInputHandling
    componentApplicationOutputHandling --> componentTheModel
    componentApplicationInputHandling --> componentApplication
    componentReasoningCore --> componentAgentOutputHandling
    componentReasoningCore --> componentOrchestrationInputHandling
    componentOrchestrationOutputHandling --> componentReasoningCore
    componentOrchestrationOutputHandling --> componentTheModel
    componentOrchestrationInputHandling --> componentTools
    componentOrchestrationInputHandling --> componentMemory
    componentOrchestrationInputHandling --> componentRAGContent
    componentTools --> componentOrchestrationOutputHandling
    componentMemory --> componentOrchestrationOutputHandling
    componentRAGContent --> componentOrchestrationOutputHandling
    componentAgentUserQuery --> componentAgentInputHandling
    componentAgentSystemInstruction --> componentAgentInputHandling
    componentAgentInputHandling --> componentReasoningCore
    componentAgentOutputHandling --> componentApplication
    componentAgentOutputHandling --> componentTheModel

%% Node style definitions
    style componentsInfrastructure fill:#e6f3e6,stroke:#333333,stroke-width:2px
    style componentsApplication fill:#e6f0ff,stroke:#333333,stroke-width:2px
    style componentsModel fill:#ffe6e6,stroke:#333333,stroke-width:2px
```
