```mermaid
---
config:
  layout: elk
  elk:
    mergeEdges: True
    nodePlacementStrategy: NETWORK_SIMPLEX
---

graph LR
   %%{init: {'flowchart': {'nodeSpacing': 25, 'rankSpacing': 150, 'padding': 5, 'wrappingWidth': 250}}}%%
    classDef hidden display: none;
    classDef allControl stroke:#4285f4,stroke-width:2px,stroke-dasharray: 5 5

    subgraph controls
    subgraph controlsData ["Data Controls"]
        controlModelPrivacyEnhancingTechnologies[Privacy Enhancing Technologies for Model Training]
        controlRetrievalAndVectorSystemIntegrity[Retrieval and Vector System Integrity Management]
        controlRuntimePrivacyEnhancingTechnologies[Privacy Enhancing Technologies for Inference]
        controlTrainingDataManagement[Training Data Management]
        controlTrainingDataSanitization[Training Data Sanitization]
        controlUserDataManagement[User Data Management]
    end

    subgraph controlsInfrastructure ["Infrastructure Controls"]
        controlComponentIdentityProvenance[Component Identity Provenance]
        controlInterComponentTransportSecurity[Inter-Component Transport Security]
        controlIsolatedConfidentialComputing[Isolated and Confidential Computing]
        controlModelAndDataAccessControls[Model and Data Access Controls]
        controlModelAndDataExecutionIntegrity[Model and Data Execution Integrity]
        controlModelAndDataIntegrityManagement[Model and Data Integrity Management]
        controlModelAndDataInventoryManagement[Model and Data Inventory Management]
        controlModelRegistryIntegrity[Model Registry and Discovery Integrity]
        controlOrchestratorAndRouteIntegrity[Orchestrator and Route Integrity]
        controlSecureByDefaultMLTooling[Secure-by-Default ML Tooling]
        controlToolRegistryAndDiscoveryIntegrity[Tool Registry and Discovery Integrity]
    end

    subgraph controlsModel ["Model Controls"]
        controlAdversarialTrainingAndTesting[Adversarial Training and Testing]
        controlInputValidationAndSanitization[Input Validation and Sanitization]
        controlOutputValidationAndSanitization[Output Validation and Sanitization]
    end

    subgraph controlsApplication ["Application Controls"]
        controlAgentCredentialIsolation[Agent Credential Isolation]
        controlAgentExecutionBounds[Agent Execution Bounds]
        controlAgentIntegrityManagement[Agent Integrity Management]
        controlAgentInventoryManagement[Agent Inventory Management]
        controlAgentObservability[Agent Observability]
        controlAgentPluginPermissions[Agent Permissions]
        controlAgentPluginUserControl[Agent User Control]
        controlApplicationAccessManagement[Application Access and Resource Management]
        controlUserTransparencyAndControls[User Transparency and Controls]
    end

    subgraph controlsAssurance ["Assurance Controls"]
        controlIncidentResponseManagement[Incident Response Management]
        controlRedTeaming[Red Teaming]
        controlThreatDetection[Threat Detection]
        controlVulnerabilityManagement[Vulnerability Management]
    end

    subgraph controlsGovernance ["Governance Controls"]
        direction LR
        controlInternalPoliciesAndEducation[Internal Policies and Education]
        controlProductGovernance[Product Governance]
        controlRiskGovernance[Risk Governance]
        controlUserPoliciesAndEducation[User Policies and Education]
    end

    end

    subgraph components
    subgraph componentsInfrastructure ["Infrastructure Components"]
        componentDataFilteringAndProcessing[Data Filtering and Processing]
        componentDataSources[Data Sources]
        componentDataStorage[Data Storage Infrastructure]
        componentToolRegistry[Tool Registry and Discovery]
        componentTrainingData[Training Data]
        subgraph componentsModelInfrastructure ["Model Infrastructure"]
            componentModelRegistry[Model Registry and Marketplace]
            componentModelServing[Model Serving Infrastructure]
            componentModelStorage[Model Storage]
        end
    end

    subgraph componentsModel ["Model Components"]
        componentMemory[Model Memory]
        componentModelFrameworksAndCode[Model Frameworks and Code]
        componentRAGContent[Retrieval Augmented Generation & Content]
        componentTheModel[The Model]
        subgraph componentsModelSubgroup ["Model Subgroup"]
            componentModelEvaluation[Model Evaluation]
            componentModelTrainingTuning[Training and Tuning]
        end
        subgraph componentsOrchestration ["Orchestration"]
            componentOrchestrationInputHandling[Input Handling]
            componentOrchestrationOutputHandling[Output Handling]
        end
    end

    subgraph componentsApplication ["Application Components"]
        componentAgentInputHandling[Input Handling]
        componentAgentOutputHandling[Output Handling]
        componentAgentSystemInstruction[Agent System Instructions]
        componentAgentUserQuery[Agent User Query]
        componentApplication[Application]
        componentApplicationInputHandling[Input Handling]
        componentApplicationOutputHandling[Output Handling]
        componentReasoningCore[Agent Reasoning Core]
    end

    subgraph componentsExternalTools ["External Tools Components"]
        componentTools[External Tools and Services]
    end

    end

    %% Control to Component relationships
    controlModelPrivacyEnhancingTechnologies --> componentsModelSubgroup
    controlRuntimePrivacyEnhancingTechnologies --> componentApplicationOutputHandling
    controlRuntimePrivacyEnhancingTechnologies --> componentModelServing
    controlTrainingDataManagement --> componentDataSources
    controlTrainingDataManagement --> componentTrainingData
    controlTrainingDataManagement --> componentsModelSubgroup
    controlTrainingDataSanitization --> componentDataFilteringAndProcessing
    controlUserDataManagement --> componentDataStorage
    controlModelAndDataInventoryManagement --> componentsModelInfrastructure
    controlModelAndDataInventoryManagement --> componentsModelSubgroup
    controlModelAndDataAccessControls --> componentModelServing
    controlModelAndDataAccessControls --> componentModelStorage
    controlModelAndDataAccessControls --> componentsModelSubgroup
    controlModelAndDataIntegrityManagement --> componentsModelInfrastructure
    controlModelAndDataIntegrityManagement --> componentsModelSubgroup
    controlModelAndDataExecutionIntegrity --> componentModelServing
    controlModelAndDataExecutionIntegrity --> componentModelStorage
    controlModelAndDataExecutionIntegrity --> componentTheModel
    controlSecureByDefaultMLTooling --> componentModelServing
    controlSecureByDefaultMLTooling --> componentModelStorage
    controlSecureByDefaultMLTooling --> componentsModelSubgroup
    controlInputValidationAndSanitization --> componentAgentInputHandling
    controlInputValidationAndSanitization --> componentApplicationInputHandling
    controlInputValidationAndSanitization --> componentOrchestrationInputHandling
    controlOutputValidationAndSanitization --> componentAgentOutputHandling
    controlOutputValidationAndSanitization --> componentApplicationOutputHandling
    controlOutputValidationAndSanitization --> componentOrchestrationOutputHandling
    controlAdversarialTrainingAndTesting --> componentTheModel
    controlApplicationAccessManagement --> componentApplication
    controlUserTransparencyAndControls --> componentApplication
    controlAgentPluginUserControl --> componentReasoningCore
    controlAgentPluginPermissions --> componentMemory
    controlAgentPluginPermissions --> componentRAGContent
    controlAgentPluginPermissions --> componentReasoningCore
    controlAgentPluginPermissions --> componentsExternalTools
    controlRedTeaming -.-> components
    controlVulnerabilityManagement -.-> components
    controlThreatDetection -.-> components
    controlIncidentResponseManagement -.-> components
    controlAgentObservability --> componentAgentInputHandling
    controlAgentObservability --> componentAgentOutputHandling
    controlAgentObservability --> componentReasoningCore
    controlAgentObservability --> componentsOrchestration
    controlIsolatedConfidentialComputing --> componentMemory
    controlIsolatedConfidentialComputing --> componentModelServing
    controlIsolatedConfidentialComputing --> componentModelTrainingTuning
    controlIsolatedConfidentialComputing --> componentReasoningCore
    controlRetrievalAndVectorSystemIntegrity --> componentDataFilteringAndProcessing
    controlRetrievalAndVectorSystemIntegrity --> componentDataSources
    controlRetrievalAndVectorSystemIntegrity --> componentDataStorage
    controlOrchestratorAndRouteIntegrity --> componentApplication
    controlOrchestratorAndRouteIntegrity --> componentModelServing
    controlAgentInventoryManagement --> componentReasoningCore
    controlAgentInventoryManagement --> componentsExternalTools
    controlAgentInventoryManagement --> componentsOrchestration
    controlAgentIntegrityManagement --> componentModelServing
    controlAgentIntegrityManagement --> componentOrchestrationInputHandling
    controlAgentIntegrityManagement --> componentReasoningCore
    controlAgentIntegrityManagement --> componentsExternalTools
    controlAgentCredentialIsolation --> componentMemory
    controlAgentCredentialIsolation --> componentReasoningCore
    controlAgentCredentialIsolation --> componentsExternalTools
    controlAgentCredentialIsolation --> componentsOrchestration
    controlInterComponentTransportSecurity --> componentApplication
    controlInterComponentTransportSecurity --> componentModelServing
    controlInterComponentTransportSecurity --> componentsExternalTools
    controlInterComponentTransportSecurity --> componentsOrchestration
    controlComponentIdentityProvenance --> componentApplication
    controlComponentIdentityProvenance --> componentModelServing
    controlComponentIdentityProvenance --> componentsExternalTools
    controlComponentIdentityProvenance --> componentsOrchestration
    controlAgentExecutionBounds --> componentReasoningCore
    controlAgentExecutionBounds --> componentsOrchestration
    controlModelRegistryIntegrity --> componentModelRegistry
    controlToolRegistryAndDiscoveryIntegrity --> componentToolRegistry

    %% Apply styling to controls mapped to 'all'
    controlIncidentResponseManagement:::allControl
    controlRedTeaming:::allControl
    controlThreatDetection:::allControl
    controlVulnerabilityManagement:::allControl

    %% Edge styling
    linkStyle 35,36,37,38 stroke:#4285f4,stroke-width:3px,stroke-dasharray: 8 4
    linkStyle 0,5,8,9,12,13,14,20,34,42,53,54,58,61,62,65,66,69,70,72 stroke:#34a853,stroke-width:2px
    linkStyle 3,10,15,18,21,24,31,39,43,47,52,55,59,63,67 stroke:#9c27b0,stroke-width:2px
    linkStyle 4,11,16,19,22,25,32,40,44,48,56,60,64,68 stroke:#ff9800,stroke-width:2px,stroke-dasharray: 5 5
    linkStyle 17,23,26,33,41,45,49,57 stroke:#e91e63,stroke-width:2px,stroke-dasharray: 10 2
    linkStyle 46 stroke:#C95792,stroke-width:2px,stroke-dasharray: 10 5

%% Node style definitions
    style components fill:#f0f0f0,stroke:#666666,stroke-width:3px,stroke-dasharray: 10 5
    style controls fill:#f0f0f0,stroke:#666666,stroke-width:3px,stroke-dasharray: 10 5
    style componentsInfrastructure fill:#e6f3e6,stroke:#333333,stroke-width:2px
    style componentsApplication fill:#e6f0ff,stroke:#333333,stroke-width:2px
    style componentsModel fill:#ffe6e6,stroke:#333333,stroke-width:2px
    style componentsExternalTools fill:#f3e6ff,stroke:#333333,stroke-width:2px
    style componentsModelInfrastructure fill:#d4e6d4,stroke:#333,stroke-width:1px
    style componentsModelSubgroup fill:#f0e6e6,stroke:#333,stroke-width:1px
    style componentsOrchestration fill:#f0e6e6,stroke:#333,stroke-width:1px
```
