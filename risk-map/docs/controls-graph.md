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
        controlPrivacyEnhancingTechnologies[Privacy Enhancing Technologies]
        controlRetrievalAndVectorStorePoisoningDefense[Retrieval and Vector Store Poisoning Defense]
        controlTrainingDataManagement[Training Data Management]
        controlTrainingDataSanitization[Training Data Sanitization]
        controlUserDataManagement[User Data Management]
    end

    subgraph controlsInfrastructure ["Infrastructure Controls"]
        controlAcceleratorIsolationAndSideChannelMitigation[Accelerator Isolation and Side-channel Mitigation]
        controlModelAndDataAccessControls[Model and Data Access Controls]
        controlModelAndDataIntegrityManagement[Model and Data Integrity Management]
        controlModelAndDataInventoryManagement[Model and Data Inventory Management]
        controlModelRepositoryTrustAndAttestation[Model Repository Trust and Attestation]
        controlOrchestratorAndRouteIntegrity[Orchestrator and Route Integrity]
        controlSecureByDefaultMLTooling[Secure-by-Default ML Tooling]
    end

    subgraph controlsModel ["Model Controls"]
        controlAdapterIntegrityAndAllowlisting[Adapter Integrity and Allowlisting]
        controlAdversarialTrainingAndTesting[Adversarial Training and Testing]
        controlEvaluationProvenanceAndDriftDetection[Evaluation Provenance and Drift Detection]
        controlFederatedTrainingPrivacyAndRobustAggregation[Federated Training Privacy and Robust Aggregation]
        controlInputValidationAndSanitization[Input Validation and Sanitization]
        controlOutputValidationAndSanitization[Output Validation and Sanitization]
    end

    subgraph controlsApplication ["Application Controls"]
        controlAgentPluginPermissions[Agent/Plugin Permissions]
        controlAgentPluginUserControl[Agent/Plugin User Control]
        controlApplicationAccessManagement[Application Access Management]
        controlCostQuotaGuardrails[Cost Quota Guardrails]
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
        componentTrainingData[Training Data]
        subgraph componentsModels ["Models"]
            componentModelServing[Model Serving Infrastructure]
            componentModelStorage[Model Storage]
        end
    end

    subgraph componentsModel ["Model Components"]
        componentInputHandling[Input Handling]
        componentModelFrameworksAndCode[Model Frameworks and Code]
        componentOutputHandling[Output Handling]
        componentTheModel[The Model]
        subgraph componentsModelSubgroup ["Model Subgroup"]
            componentModelEvaluation[Model Evaluation]
            componentModelTrainingTuning[Training and Tuning]
        end
    end

    subgraph componentsApplication ["Application Components"]
        componentAgentPlugin[Agent/Plugin]
        componentApplication[Application]
    end

    end

    %% Control to Component relationships
    controlPrivacyEnhancingTechnologies --> componentOutputHandling
    controlPrivacyEnhancingTechnologies --> componentsModelSubgroup
    controlTrainingDataManagement --> componentDataSources
    controlTrainingDataManagement --> componentTrainingData
    controlTrainingDataManagement --> componentsModelSubgroup
    controlTrainingDataSanitization --> componentDataFilteringAndProcessing
    controlUserDataManagement --> componentDataStorage
    controlModelAndDataInventoryManagement --> componentsModelSubgroup
    controlModelAndDataInventoryManagement --> componentsModels
    controlModelAndDataAccessControls --> componentsModelSubgroup
    controlModelAndDataAccessControls --> componentsModels
    controlModelAndDataIntegrityManagement --> componentsModelSubgroup
    controlModelAndDataIntegrityManagement --> componentsModels
    controlSecureByDefaultMLTooling --> componentsModelSubgroup
    controlSecureByDefaultMLTooling --> componentsModels
    controlInputValidationAndSanitization --> componentInputHandling
    controlOutputValidationAndSanitization --> componentOutputHandling
    controlAdversarialTrainingAndTesting --> componentTheModel
    controlApplicationAccessManagement --> componentApplication
    controlUserTransparencyAndControls --> componentApplication
    controlAgentPluginUserControl --> componentAgentPlugin
    controlAgentPluginPermissions --> componentAgentPlugin
    controlRedTeaming -.-> components
    controlVulnerabilityManagement -.-> components
    controlThreatDetection -.-> components
    controlIncidentResponseManagement -.-> components
    controlAcceleratorIsolationAndSideChannelMitigation --> componentModelServing
    controlAcceleratorIsolationAndSideChannelMitigation --> componentModelTrainingTuning
    controlRetrievalAndVectorStorePoisoningDefense --> componentDataFilteringAndProcessing
    controlRetrievalAndVectorStorePoisoningDefense --> componentDataSources
    controlRetrievalAndVectorStorePoisoningDefense --> componentDataStorage
    controlAdapterIntegrityAndAllowlisting --> componentTheModel
    controlAdapterIntegrityAndAllowlisting --> componentsModels
    controlFederatedTrainingPrivacyAndRobustAggregation --> componentsModelSubgroup
    controlOrchestratorAndRouteIntegrity --> componentApplication
    controlOrchestratorAndRouteIntegrity --> componentModelServing
    controlModelRepositoryTrustAndAttestation --> componentsModels
    controlCostQuotaGuardrails --> componentApplication
    controlCostQuotaGuardrails --> componentModelServing
    controlEvaluationProvenanceAndDriftDetection --> componentsModelSubgroup

    %% Apply styling to controls mapped to 'all'
    controlIncidentResponseManagement:::allControl
    controlRedTeaming:::allControl
    controlThreatDetection:::allControl
    controlVulnerabilityManagement:::allControl

    %% Edge styling
    linkStyle 22,23,24,25 stroke:#4285f4,stroke-width:3px,stroke-dasharray: 8 4
    linkStyle 1,4,7,8,9,10,11,12,13,14,32,33,36,39 stroke:#34a853,stroke-width:2px
    linkStyle 2,28 stroke:#9c27b0,stroke-width:2px
    linkStyle 3,29 stroke:#ff9800,stroke-width:2px,stroke-dasharray: 5 5
    linkStyle 30 stroke:#e91e63,stroke-width:2px,stroke-dasharray: 10 2

%% Node style definitions
    style components fill:#f0f0f0,stroke:#666666,stroke-width:3px,stroke-dasharray: 10 5
    style controls fill:#f0f0f0,stroke:#666666,stroke-width:3px,stroke-dasharray: 10 5
    style componentsInfrastructure fill:#e6f3e6,stroke:#333333,stroke-width:2px
    style componentsApplication fill:#e6f0ff,stroke:#333333,stroke-width:2px
    style componentsModel fill:#ffe6e6,stroke:#333333,stroke-width:2px
    style componentsModels fill:#d4e6d4,stroke:#333,stroke-width:1px
    style componentsModelSubgroup fill:#f0e6e6,stroke:#333,stroke-width:1px
```
