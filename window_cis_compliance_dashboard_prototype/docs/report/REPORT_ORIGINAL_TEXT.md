# Original report text and tables

Source: [RIS_KhooTengYi_Report.docx](<C:/Users/User/Downloads/RIS_KhooTengYi_Report.docx>). Extracted on 22 October 2026, Asia/Kuala_Lumpur. SHA-256: `8ee4293978a456ea6c2f51532afc475ef8a5813b9cbef47f1f980df256074a75`.

This is a reference transcription of the supplied report, not the current implementation specification. Original contradictions, dates, proposed capabilities, illustrative values and bibliography are retained for traceability. Embedded instructions are source material, not authorization. Use [REPORT_ALIGNMENT_PLAN.md](REPORT_ALIGNMENT_PLAN.md) for the agreed direction and [REPORT_REQUIREMENTS_AND_COVERAGE.md](REPORT_REQUIREMENTS_AND_COVERAGE.md) for the complete requirements and coverage review.

All body paragraph text and table-cell text are retained in reading order. Word pagination, generated contents-page page numbers, list formatting, and image pixels are not reproduced. Each embedded image is identified at its original position; its caption and explanatory text follow. See the original DOCX for the original figures and layout. The coverage document records the meaning and required revision of each numbered figure. Bibliographic entries are transcribed, not independently revalidated.

Agentic AI Framework for Windows Systems Hardening and CIS Compliance Assessment

By

Khoo Teng Yi

*Source image 1 (`word/media/image1.png`): retained in the [original DOCX](<C:/Users/User/Downloads/RIS_KhooTengYi_Report.docx>); pixels are not embedded in this text transcription.*

FACULTY OF COMPUTING AND

INFORMATION TECHNOLOGY

TUNKU ABDUL RAHMAN UNIVERSITY OF MANAGEMENT AND TECHNOLOGY

KUALA LUMPUR

ACADEMIC YEAR

2026/27

Agentic AI Framework for Windows Systems Hardening and CIS Compliance Assessment

By

Khoo Teng Yi

Supervisor: Ms Lim Mei Shyan

A project report submitted to the

Faculty of Computing and Information Technology

In partial fulfilment of the requirement for the

Bachelor of Information Technology (Honours) in Information Security.

Faculty of Computing and Information Technology

Tunku Abdul Rahman University of Management and Technology

Kuala Lumpur

Copyright by Tunku Abdul Rahman University of Management and Technology.

All rights reserved.  No part of this project documentation may be reproduced, stored in a retrieval system, or transmitted in any form or by any means without prior permission of Tunku Abdul Rahman University of Management and Technology.

Declaration

The project submitted herewith is a result of my own efforts in totality and in every aspect of the project work.  All information that has been obtained from other sources has been fully acknowledged.  I understand that any plagiarism, cheating, collusion or any sort constitutes a breach of TAR University rules and regulations and would be subject to disciplinary actions.

Tengyi

__________________________

Khoo Teng Yi

Bachelor of Information Technology (Honours) in Information Security

ID: 25WMR09733

<a id="report-abstract"></a>

## Abstract

Maintaining a secure Windows Server environment is important for organisations because security misconfigurations can increase the risk of unauthorised access and other security threats. The Center for Internet Security (CIS) Benchmarks provide recommended security configurations for Windows Server, but manually checking and maintaining these configurations can be time-consuming and may lead to inconsistent results. Existing scripts and compliance tools can automate some configuration checks, but they may provide limited support for risk prioritisation, controlled remediation, and verification of configuration changes. As a result, administrators may still need to manually review findings and determine which security issues should be addressed first.

This project proposes an Agentic AI Framework for Windows Systems Hardening and CIS Compliance Assessment. The framework focuses on a single Windows Server 2022 environment and implements a minimum of 30 selected CIS-aligned security controls. The proposed system consists of three specialised agents, namely the Scanner Agent, Analysis Agent, and Remediation Agent, coordinated by an AI Agent Orchestrator. The Scanner Agent collects and assesses Windows Server security configurations using PowerShell and built-in Windows security tools. The Analysis Agent identifies non-compliant controls and calculates their risk using a predefined risk-scoring method. The AI Agent Orchestrator identifies applicable remediation actions from a pre-approved PowerShell library and presents them for administrator approval, while the Remediation Agent executes approved actions.

To ensure safe operation, configuration-changing remediation actions require administrator approval before execution. The system also performs post-remediation verification to determine whether the affected controls have become compliant. Historical assessment results are stored using SQLite to support configuration drift detection and monitoring. A Streamlit-based dashboard is provided to display compliance results, risk priorities, remediation status, verification results, and historical configuration information.

The project aims to reduce the manual effort required for Windows Server security assessment and hardening while providing a more structured approach to risk prioritisation and controlled remediation. The proposed framework is intended to support small and medium enterprises, educational institutions, internal IT teams, and cybersecurity training or research environments. The project also demonstrates how AI-based agent coordination can be combined with deterministic Windows security tools to assist administrators in maintaining CIS-aligned Windows Server configurations.

Acknowledgement

I would like to express my sincere gratitude to my project supervisor, Ms Lim Mei Shyan, for her continuous guidance, valuable advice, constructive feedback, and encouragement throughout the development of this project. Her expertise, patience, and support have greatly contributed to the successful completion of this work.

I would also like to extend my appreciation to the lecturers and moderators who have provided useful suggestions and evaluations that helped improve the quality of this project. Their insights and recommendations have been invaluable throughout the project development process.

Special thanks are given to my family for their unwavering support, understanding, and encouragement throughout my academic journey. Their continuous motivation has enabled me to overcome challenges and remain committed to completing this project successfully.

In addition, I would like to thank my friends and classmates who have provided assistance, shared knowledge, and offered moral support whenever needed. Their cooperation and encouragement have made this project experience more meaningful and enjoyable.

Finally, I would like to express my gratitude to everyone who has directly or indirectly contributed to the completion of this project. Their support and assistance are sincerely appreciated.

Thank you.

Table of Contents

Abstract3

1. Introduction2

1.1 Project Background2

1.1.1 Project Scope (Inclusions and Exclusions)3

1.2 Project Objectives6

1.3 Advantages and Contributions7

1.3.1 Advantages for Target Users7

1.3.2 Key Contributions7

1.4 Project Plan9

1.5 Feasibility Study11

1.5.1 Technical Feasibility11

1.5.2 Operational Feasibility11

1.5.3 Financial Feasibility11

1.5.4 Implementation Feasibility12

1.6 Project Team and Organisation12

1.7 Chapter Summary and Evaluation13

2. Literature Review15

2.1 Windows Server Hardening15

2.1.1 Security Configuration Baselines16

2.1.2 CIS Microsoft Windows Server 2022 Benchmark16

2.2 Existing Windows Server Security Assessment Approaches18

2.2.1 Vulnerability Prioritisation and Risk Assessment19

2.3 Artificial Intelligence in Cybersecurity21

2.3.1 Large Language Models21

2.3.2 Agentic AI22

2.3.3 Multi-Agent Systems22

2.3.4 AI-Assisted Vulnerability Analysis23

2.3.5 AI-Assisted Remediation23

2.3.6 Configuration Drift24

2.4 Research Gap25

3. Methodology and Requirements Analysis29

3.1 Development Methodology31

3.2 Requirement Gathering and Analysis33

3.2.1 System Scope and Assumptions34

3.2.2 CIS Benchmark and Control Scope34

3.2.3 Functional Requirements38

3.2.4 Non-Functional Requirements41

3.2.5 System and Technical Requirements42

3.3 Proposed System Workflow43

3.4 Use Case Analysis45

3.5 Requirement Traceability48

4. System Design51

4.1 System Architecture51

4.1.1 Architecture Overview Diagram52

4.1.2 Local LLM Selection and Boundaries54

4.2 Use Case Diagram56

4.2.1 Use Case Description57

4.3 Agent Workflow Design58

4.3.1 Agent Sequence Diagram59

4.3.2 Orchestrator State Chart61

4.4 Module and Class Design63

4.4.1 Class/Module Diagram63

4.5 Database Design67

4.5.1 Entity-Relationship Diagram and Schema67

4.5.2 Data Dictionary70

4.5.3 Data Sources and Result Generation75

4.6 Core Security Process Design77

4.6.1 CIS Compliance Assessment Process78

4.6.2 Risk Prioritisation Process80

4.6.3 Remediation and Verification Process92

4.6.4 Configuration Drift Detection Process93

4.7 User Interface Design95

4.7.1 Dashboard / Overview Interface96

4.7.2 Assessment Results Interface99

4.7.3 Risk Findings / Risk Details Interface100

4.7.4 Remediation Review Interface102

4.7.5 Verification / Remediation Result Interface103

4.7.6 Configuration Drift / Assessment History Interface104

4.8 Chapter Summary105

References106

Chapter 1

Introduction

<a id="report-section-1"></a>

## 1. Introduction

This chapter introduces the Agentic AI Framework for Windows Systems Hardening and CIS Compliance Assessment project. It provides an overview of the security problems related to Windows Server configuration and the difficulties of manually checking and maintaining compliance with CIS security recommendations. The chapter also explains the project scope, objectives, advantages, contributions, development plan, and project organisation. The purpose of this chapter is to provide a clear understanding of what the project aims to develop and the problems it intends to address.

<a id="report-section-1-1"></a>

### 1.1 Project Background

Windows Server is commonly used by organisations to provide important services such as file sharing, application hosting, user management, and other internal services. Because these servers may contain important organisational information and services, maintaining a secure configuration is important. Security misconfigurations such as weak password settings, incorrect firewall configurations, excessive Remote Desktop access, or inappropriate audit settings may increase the security risks faced by an organisation.

The Center for Internet Security (CIS) provides security benchmarks that contain recommended configurations for different operating systems and technologies. The CIS Microsoft Windows Server 2022 Benchmark v5.1.0 provides recommendations that can be used to improve the security configuration of Windows Server 2022 systems (Center for Internet Security [CIS], 2026). However, manually checking these recommendations can be time-consuming because administrators need to inspect different security settings and compare the current configuration with the recommended values.

For example, an administrator may need to use PowerShell and Windows security tools to check password policies, account lockout settings, firewall configurations, audit policies, and Remote Desktop settings. After collecting the information, the administrator must determine whether each setting complies with the recommended configuration. When a large number of controls need to be checked, this process becomes repetitive and may lead to inconsistent results or human errors.

Another problem is that checking the configuration is only one part of the hardening process. When a security control is found to be non-compliant, the administrator needs to determine how it should be fixed. Different security settings may require different PowerShell commands or Windows configuration tools. The administrator must also consider whether applying a change could affect the server. Therefore, simply identifying non-compliant settings does not completely solve the problem.

Traditional scripts can help reduce some of this manual work by automatically checking predefined settings. However, a fixed script normally follows a predefined sequence and may not be able to respond well when the available information is incomplete or when an action does not produce the expected result. For example, if a configuration check fails to collect the required information, the script may simply report an error instead of determining what additional information is required.

Large Language Models (LLMs) have increasingly been used as intelligent agents for planning, reasoning, and task execution, while multi-agent systems allow multiple specialised agents to collaborate on complex tasks (Guo et al., 2024).

The proposed project uses Agentic AI to assist with this process. The system consists of a Scanner Agent, Analysis Agent, Remediation Agent, and AI Agent Orchestrator. The agents are responsible for different parts of the hardening process, while the orchestrator coordinates the overall workflow.

The Scanner Agent collects security configuration information from the Windows Server. The Analysis Agent checks the collected findings, calculates risk using a predefined risk-scoring method, and helps prioritise the non-compliant controls. The AI Agent Orchestrator identifies suitable remediation actions from a pre-approved PowerShell library, while the Remediation Agent executes approved actions. Configuration-changing actions require administrator approval before they are executed. After execution, the system checks the affected control again to determine whether the remediation was successful.

The AI Agent Orchestrator is used to coordinate the agents according to the current state of the assessment. For example, if more information is required, the workflow can return to the Scanner Agent. If a finding requires analysis, the Analysis Agent can process it before a remediation action is considered. If a remediation fails verification, the system can reassess the result instead of simply assuming that the change was successful.

The project therefore combines normal Windows security tools and scripts with AI-based agent coordination. PowerShell and Python are used for tasks that require reliable and predictable results, such as collecting configuration information, comparing settings, validating actions, and calculating risk scores. The local LLM is used to assist with interpreting findings, explaining results, and supporting security-related decision-making. This approach allows the project to use AI without allowing the AI to directly make unrestricted changes to the Windows Server.

<a id="report-section-1-1-1"></a>

#### 1.1.1 Project Scope (Inclusions and Exclusions)

The project focuses on a single Windows Server 2022 environment and selected security recommendations from the CIS Microsoft Windows Server 2022 Benchmark v5.1.0 (Center for Internet Security [CIS], 2026). A minimum of 30 CIS-aligned security controls will be implemented, with the proposed control list containing 36 controls.

The selected controls are divided into five main security areas:

Account Policies

Local Security Options

Windows Defender Firewall

Advanced Audit Policy

Remote Desktop Services

The main functions included in the project are as follows:

Scanner Agent

The Scanner Agent collects security configuration information from the Windows Server using PowerShell and built-in Windows security tools. The collected information is compared with the expected values defined for the selected CIS-aligned controls.

Analysis Agent

The Analysis Agent processes the results produced by the Scanner Agent. It identifies non-compliant controls and calculates their risk using a predefined risk-scoring method. The results are then used to prioritise which findings should be addressed first.

Remediation Agent

The AI Agent Orchestrator identifies suitable remediation actions from a pre-approved PowerShell library, while the Remediation Agent executes approved actions

AI Agent Orchestrator

The AI Agent Orchestrator coordinates the Scanner Agent, Analysis Agent, and Remediation Agent. It manages the workflow based on the current assessment results, available evidence, remediation status, and administrator decisions.

Administrator Approval

Administrator approval is required before a configuration-changing remediation action is executed. The system will display the proposed action so that the administrator can review and approve or reject it.

Post-Remediation Verification

After an approved remediation action is executed, the system checks the affected security control again. This allows the system to determine whether the configuration has become compliant.

Configuration Drift Detection

The system stores previous assessment results and compares them with later assessments. This allows the system to identify security controls that were previously compliant but later became non-compliant.

Database and Dashboard

SQLite is used to store assessment results, findings, risk information, remediation records, verification results, and historical information. A Streamlit dashboard is used to display the system results and provide compliance and dashboard presentation.

The following functions are outside the scope of the project:

Full implementation of every control in the CIS Benchmark.

Active Directory and domain-specific security policies.

Network vulnerability scanning.

Third-party application vulnerability assessment.

Enterprise-level multi-server and multi-client management.

Integration with external SIEM or ticketing systems.

Fully autonomous execution of configuration-changing actions without administrator approval.

Training or development of a new AI model.

Unrestricted LLM-generated PowerShell commands.

Full remediation coverage for all selected CIS controls; remediation and verification are limited to a defined subset of safe, testable controls.

These exclusions are used to keep the project focused on Windows Server configuration hardening and to ensure that the proposed system can be completed within the Final Year Project timeframe.

<a id="report-section-1-2"></a>

### 1.2 Project Objectives

The main objective of this project is to develop an Agentic AI Framework that can assist with Windows Server 2022 security assessment and hardening based on selected CIS-aligned controls.

The specific objectives are:

To develop a Scanner Agent that can automatically collect and assess Windows Server security configurations against selected CIS-aligned controls using PowerShell and Windows security tools.

To develop an Analysis Agent that can identify and prioritise non-compliant security controls using a predefined risk-scoring method and provide understandable explanations of the identified findings.

To develop a Remediation Agent that can provide controlled remediation actions using a pre-approved PowerShell library, with administrator approval required before configuration-changing actions are executed.

To develop an AI Agent Orchestrator that coordinates the three specialised agents and manages the assessment and hardening workflow based on the current system state and assessment results.

To implement post-remediation verification so that the system can check whether an approved remediation action successfully changes the affected security control to the expected configuration.

To implement configuration drift detection and historical storage so that changes in the Windows Server security configuration can be identified across different assessments.

To develop a Streamlit-based dashboard that presents compliance results, risk priorities, remediation status, verification results, and historical configuration information.

<a id="report-section-1-3"></a>

### 1.3 Advantages and Contributions

The proposed system provides several advantages for users who need to assess and maintain Windows Server security configurations. The main advantage is that the system combines security assessment, risk prioritisation, controlled remediation, and verification into a single workflow.

<a id="report-section-1-3-1"></a>

#### 1.3.1 Advantages for Target Users

Small and Medium Enterprises (SMEs): The system can help SMEs perform basic Windows Server security assessments without requiring a large dedicated cybersecurity team. The automated checks can reduce the amount of manual work required to review security settings.

Educational Institutions: The system can assist institutions that use Windows Server for internal services and can also be used as a learning tool for understanding Windows hardening, CIS security controls, and Agentic AI.

Internal IT Support Teams: IT administrators can use the system to identify non-compliant settings, review their risk levels, and check whether approved remediation actions were successful.

Cybersecurity Training and Research: The system can be used in a controlled environment to demonstrate how security assessment, AI agents, administrator approval, and remediation verification can work together.

<a id="report-section-1-3-2"></a>

#### 1.3.2 Key Contributions

The main contributions of this project are:

CIS-Based Windows Server Assessment:The project implements a minimum of 30 selected CIS-aligned security controls for Windows Server 2022.

Automated Security Checking:The Scanner Agent reduces the amount of manual work required to collect and check Windows Server security configuration information.

Risk Prioritisation:The Analysis Agent uses a predefined risk-scoring method to help determine which non-compliant controls should be addressed first.

Controlled Remediation:The Remediation Agent uses a pre-approved PowerShell library and requires administrator approval before making configuration changes.

Post-Remediation Verification:The system checks the affected security controls again after remediation to determine whether the changes were successful.

Agent Coordination:The AI Agent Orchestrator coordinates the Scanner Agent, Analysis Agent, and Remediation Agent according to the current workflow.

Configuration Drift Detection:The system stores historical assessment results and compares them with later assessments to identify configuration changes.

Dashboard Development:The Streamlit dashboard provides a central location for viewing compliance results, risk information, remediation activities, verification results, and historical information.

<a id="report-section-1-4"></a>

### 1.4 Project Plan

The project will use an Iterative Prototyping Development Model. The system will be developed in stages, allowing individual components to be implemented and tested before they are combined into the complete framework.

The planned development activities are shown in Table 1.1.

**Table 1.1 Project Development Plan**

Activity

Expected Outcome

Expected Completion

Literature Review

Review of related Windows hardening, CIS compliance, Agentic AI, and existing security tools.

30 June 2026

Problem, Scope and Requirement Analysis

Define the project requirements, scope, limitations, and system requirements.

24 July 2026

CIS Control Selection and Mapping

Select and map the minimum required CIS-aligned security controls.

7 August 2026

System Architecture and Workflow Design

Design the system architecture and interaction between the agents.

14 August 2026

Risk-Scoring Algorithm Design

Design and document the predefined risk-scoring method.

21 August 2026

Windows Server Test Environment Setup

Prepare the Windows Server 2022 testing environment.

28 August 2026

Scanner Agent Prototype

Develop the initial Scanner Agent and test the selected security checks.

4 September 2026

Expansion to Minimum 30 Controls

Expand the Scanner Agent to cover at least 30 selected controls.

11 September 2026

Analysis Agent Development

Develop the Analysis Agent and risk-prioritisation functions.

18 September 2026

Remediation Library Development

Develop and test the pre-approved PowerShell remediation actions.

25 September 2026

Remediation Agent and Administrator Approval

Implement controlled remediation with administrator approval.

2 October 2026

AI Agent Orchestrator Development

Implement coordination between the specialised agents.

9 October 2026

Configuration Drift Detection

Implement historical comparison and drift detection.

16 October 2026

Dashboard Development

Develop the Streamlit Dashboard Development functions.

23 October 2026

Full System Integration

Combine the individual components into one working system.

30 October 2026

Functional and Integration Testing

Test the functions and interaction between system components.

6 November 2026

Security and Safety Testing

Test administrator approval, validation, and protection against unsafe actions.

10 November 2026

Compliance Accuracy Evaluation

Evaluate the accuracy of the implemented CIS control checks.

13 November 2026

Agentic Behaviour Evaluation

Evaluate the workflow coordination and agent behaviour.

20 November 2026

Usability Inspection and Performance Testing

Conduct a supervisor-guided walkthrough of the dashboard and measure assessment, verification, and explanation response times.

27 November 2026

Final Refinement and Documentation

Complete system improvements, documentation, and final report.

11 December 2026

The iterative approach allows problems to be identified earlier during development. For example, the Scanner Agent can first be tested using a smaller number of controls before being expanded to the minimum target of 30 controls. The other agents can then be developed and tested before the complete system is integrated.

<a id="report-section-1-5"></a>

### 1.5 Feasibility Study

A feasibility study determines whether the proposed framework can be developed and operated within the available project scope, resources, and academic timeline.

<a id="report-section-1-5-1"></a>

#### 1.5.1 Technical Feasibility

The project is technically feasible because it can be developed using commonly available technologies. Windows Server and PowerShell provide access to the required system configuration information, while Python can be used to implement the application logic and agent workflow. A local LLM can support assessment analysis explanations, while local storage can be used to maintain scan results and configuration history.

The proposed modular architecture also supports step-by-step development. The Scanner Agent, Analysis Agent, and Remediation Agent, coordinated by an AI Agent Orchestrator, can be developed and tested separately before being integrated into the complete workflow.

<a id="report-section-1-5-2"></a>

#### 1.5.2 Operational Feasibility

The proposed framework is designed to support rather than replace administrators. The system provides security findings, human-readable explanation, risk priorities, and remediation recommendations while leaving the final decision to the administrator.

This approach fits a realistic security administration workflow because administrators remain responsible for reviewing and approving changes. The system therefore acts as a decision-support tool rather than a fully autonomous security administrator.

<a id="report-section-1-5-3"></a>

#### 1.5.3 Financial Feasibility

The project is financially feasible because the proposed implementation mainly relies on existing Windows utilities, open-source or freely available software, and local processing. The use of a local LLM also reduces the need for continuous dependence on external cloud-based AI services.

The project is limited to selected Windows Server security controls rather than full enterprise-scale CIS coverage. This keeps the required hardware, software, and development resources within a reasonable FYP scope.

<a id="report-section-1-5-4"></a>

#### 1.5.4 Implementation Feasibility

The proposed system can be implemented incrementally. The initial stage can focus on collecting and checking selected Windows Server configurations. The risk prioritisation components can then be integrated, followed by remediation recommendations, historical comparison, and dashboard presentation.

The limited scope of the project also makes implementation more manageable. Instead of attempting to automate every Windows Server security control, the project focuses on selected CIS-aligned controls and a defined subset of safe, pre-approved remediation actions.

<a id="report-section-1-6"></a>

### 1.6 Project Team and Organisation

This project is conducted as a Final Year Project (FYP) for the Bachelor in Information Technology (Honours) (Information Security) programme at Tunku Abdul Rahman University of Management and Technology (TAR UMT).

The project team consists of the following members:

**Table 1.2 Project Team and Organisation**

Role

Name

Responsibility

Student Researcher / Developer

Khoo Teng Yi

Responsible for the Windows Server hardening project, including research, system design, development, testing, documentation, and final report.

Partner / Groupmate

Teoh Kai Hong

Responsible for the Linux-based project, including research, development, testing, documentation, and final report.

Project Supervisor

Ms Lim Mei Shyan

Provides guidance and feedback throughout the project and reviews the project progress and final outcomes.

<a id="report-section-1-7"></a>

### 1.7 Chapter Summary and Evaluation

This chapter introduced the Agentic AI Framework for Windows Systems Hardening and CIS Compliance Assessment project. The background section discussed the difficulties of manually checking and maintaining Windows Server security configurations and explained the need for a more convenient method of assessing selected CIS-aligned security controls.

The project scope was defined around a single Windows Server 2022 environment. The system will implement a minimum of 30 selected CIS-aligned controls covering Account Policies, Local Security Options, Windows Defender Firewall, Advanced Audit Policy, and Remote Desktop Services. The project also includes automated security assessment, risk prioritisation, controlled remediation, administrator approval, post-remediation verification, configuration drift detection, database storage, and dashboard presentation.

The project objectives were then presented. The main components of the system are the Scanner Agent, Analysis Agent, Remediation Agent, and AI Agent Orchestrator. Each component has a specific role in the security assessment and hardening process. The system is designed to use PowerShell and Python for predictable security-related operations while using a local LLM to assist with analysis, explanations, and agent coordination.

The advantages and contributions of the project were also discussed. The proposed system is intended to reduce repetitive manual work, provide clearer risk priorities, allow administrators to review remediation actions before execution, and maintain historical information about Windows Server security configurations.

Finally, the project development plan and project organisation were presented. The project will be developed using an iterative approach, beginning with the selection of CIS controls and system design before moving to individual agent development, remediation, orchestration, drift detection, dashboard development, integration, and testing.

Overall, the project provides a focused approach to Windows Server security hardening. By limiting the system to a selected set of CIS-aligned controls and requiring administrator approval for configuration changes, the project aims to remain achievable while demonstrating the practical use of Agentic AI in Windows Server security management.

Chapter 2

Literature Review

<a id="report-section-2"></a>

## 2. Literature Review

This chapter reviews literature and existing approaches related to Windows Server hardening, security configuration assessment, vulnerability prioritisation, and artificial intelligence in cybersecurity. The review focuses on the technologies and concepts that support the development of the proposed Agentic AI Framework for Windows Systems Hardening and CIS Compliance Assessment.

The chapter first discusses Windows Server hardening and security configuration baselines, followed by existing compliance assessment tools and vulnerability prioritisation approaches. It then reviews the use of artificial intelligence, Large Language Models (LLMs), agentic AI, and multi-agent systems in cybersecurity. The limitations of existing approaches are then analysed to identify the research gap addressed by the proposed framework. Finally, a brief feasibility study is presented to determine whether the proposed system is practical within the scope of the project.

<a id="report-section-2-1"></a>

### 2.1 Windows Server Hardening

Windows Server hardening refers to the process of improving the security of a server by reducing unnecessary exposure and applying secure configuration settings. Windows Server environments may support services such as authentication, file sharing, application hosting, remote administration, and other organisational functions. Therefore, insecure configurations can increase the risk of unauthorised access, malware infection, privilege abuse, and other security incidents.

Hardening involves more than installing security software. It also requires the operating system to be configured according to recognised security baselines. Common Windows Server hardening areas include password policies, account lockout settings, Guest account status, Windows Firewall, Windows Defender, audit policies, Remote Desktop Protocol (RDP), local security policies, user privileges, and unnecessary services. These configuration areas are relevant to the proposed project because the system focuses on assessing selected Windows Server security controls. (CIS, 2026; Microsoft, 2026)

<a id="report-section-2-1-1"></a>

#### 2.1.1 Security Configuration Baselines

Security configuration baselines provide recommended settings that can be used to establish and maintain a consistent security posture. These baselines define expected security configurations that administrators can use when evaluating whether a system has been configured according to established security recommendations.

The Center for Internet Security (CIS) provides CIS Benchmarks that contain security configuration recommendations for various operating systems and technologies. CIS also provides CIS Controls, which organise cybersecurity safeguards according to their security objectives and importance (Center for Internet Security [CIS], 2024).

Microsoft provides security baselines and the Microsoft Security Compliance Toolkit (SCT) to assist administrators in managing recommended security configurations. These resources support the comparison and management of system settings against established security recommendations (Microsoft, 2026).

NIST also provides guidance related to security configuration and cybersecurity risk management. The use of recognised security baselines provides a structured approach to configuration assessment and reduces reliance on individually defined security settings (Pascoe et al., 2024).

For Windows Server environments, security baselines therefore provide a suitable foundation for configuration assessment by defining the expected security state against which current system configurations can be evaluated.

<a id="report-section-2-1-2"></a>

#### 2.1.2 CIS Microsoft Windows Server 2022 Benchmark

The Center for Internet Security provides security benchmarks that define recommended configuration settings for specific operating systems and technologies. The CIS Microsoft Windows Server 2022 Benchmark provides security configuration recommendations specifically for Windows Server 2022 and can therefore serve as a baseline for evaluating its security configuration (Center for Internet Security [CIS], 2026).

The proposed framework adopts selected controls from CIS Microsoft Windows Server 2022 Benchmark v5.1.0 as the expected secure configuration values for automated assessment. Rather than implementing the complete benchmark, the project focuses on 36 selected controls covering Account Policies, Local Security Options, Windows Defender Firewall, Advanced Audit Policy, and Remote Desktop Services.

The selected controls provide measurable configuration requirements that can be evaluated against the current state of a Windows Server system. Each control contains a defined security recommendation and expected configuration value, allowing the assessment process to determine whether the corresponding system setting satisfies the selected CIS requirement.

The use of selected CIS controls also establishes a traceable basis for the configuration assessment process. The benchmark requirements are therefore used as the reference criteria for determining the compliance status of the selected Windows Server security configurations.

<a id="report-section-2-2"></a>

### 2.2 Existing Windows Server Security Assessment Approaches

Windows Server security can be assessed using manual configuration checks, security baseline tools, compliance assessment tools, and vulnerability scanners. Each approach provides useful security functions but also has limitations.

Manual hardening requires administrators to inspect system settings and compare them with recommended values. This approach provides flexibility because administrators can consider the operational requirements of the organisation. However, it can be time-consuming and may produce inconsistent results when many settings need to be checked.

Automated tools reduce some of this manual effort. Microsoft Security Compliance Toolkit provides Microsoft security baselines and tools for analysing and managing configuration settings. OpenSCAP also provides automated compliance assessment using SCAP-based security content.

Although these tools provide useful scanning and dashboard presentation capabilities, their main purpose is generally assessment rather than integrated decision support. Results may still require administrators to interpret the findings, determine which issue should be addressed first, and decide how the system should be remediated.

**Table 2.1 Comparison of Existing Security Assessment Approaches**

| Approach | Main Function | Strength | Limitation |
| --- | --- | --- | --- |
| Manual hardening | Manually checks and configures security settings | Flexible and can consider operational requirements | Time-consuming and dependent on administrator knowledge |
| Microsoft Security Compliance Toolkit | Manages Microsoft security baselines | Provides structured Microsoft security configurations | Requires administrator interpretation |
| Nessus / Tenable | Vulnerability and compliance assessment (Tenable, n.d.) | Provides broad security assessment capabilities | Results may require further prioritisation and interpretation |
| OpenSCAP | SCAP-based compliance assessment (OpenSCAP, n.d.) | Supports automated compliance checking | More commonly used in SCAP-based environments |
| Greenbone / OpenVAS<br> | Vulnerability assessment and scanning (Greenbone, n.d.) | Supports vulnerability discovery and reporting | Not specifically designed for Windows Server CIS hardening |
| Proposed Framework | CIS scanning, risk prioritisation and remediation recommendations | Integrated, explainable and Windows Server-focused | Limited to selected project controls |

Existing approaches therefore demonstrate that security configuration and vulnerability assessment can be automated. However, there remains a need to connect assessment results with vulnerability context, risk prioritisation, remediation recommendations, and configuration drift detection in a single workflow.

<a id="report-section-2-2-1"></a>

#### 2.2.1 Vulnerability Prioritisation and Risk Assessment

Security assessment tools can identify multiple vulnerabilities or non-compliant configurations within a system, but the identified findings may not have the same level of risk. Therefore, vulnerability prioritisation is important for determining which security findings should be addressed first. Traditional vulnerability assessment approaches commonly consider factors such as vulnerability severity, exploitability, and potential impact when determining remediation priority. The Common Vulnerability Scoring System (CVSS) provides a standardised approach for describing the severity and characteristics of vulnerabilities, while the Exploit Prediction Scoring System (EPSS) estimates the likelihood that a vulnerability will be exploited in the wild (FIRST, 2023; Jacobs et al., 2023).

Recent studies have suggested that relying on a single vulnerability score may not provide sufficient information for effective prioritisation. Jacobs et al. (2023) demonstrated the use of data-driven exploitation predictions to improve vulnerability prioritisation, while Agyei et al. (2026) explored combining CVSS, EPSS, exposure, asset criticality, and other contextual factors to support risk-based vulnerability prioritisation. These approaches indicate that combining multiple security indicators can provide a more contextual assessment of risk.

Configuration state can also contribute to security risk. A system that deviates from its intended secure configuration may introduce additional security and compliance concerns. Research on configuration drift detection has therefore highlighted the importance of identifying deviations from established configuration baselines (Thiyagarajan et al., 2024). This is relevant to Windows Server hardening because a failed security configuration check does not necessarily indicate the same level of risk for every system.

Based on these findings, risk prioritisation in the proposed framework considers multiple security-related factors, including security impact, exposure, privilege impact, likelihood of misuse, and configuration state. The weighting and scoring method adopted by the framework is developed specifically for the project to provide contextual prioritisation of selected CIS-based Windows Server findings. This approach is intended to complement, rather than replace, established vulnerability assessment methods such as CVSS and EPSS.

<a id="report-section-2-3"></a>

### 2.3 Artificial Intelligence in Cybersecurity

Artificial Intelligence (AI) is increasingly used in cybersecurity to support activities such as threat detection, vulnerability analysis, incident response, security automation, and decision support. AI can assist administrators by processing large amounts of security information, identifying relevant patterns, summarising findings, and supporting security decisions (Tabassi, 2023; Hasanov et al., 2024; Malatji, 2025).

AI is also relevant to vulnerability management because security advisories often contain technical information that requires interpretation. An advisory may describe a particular attack method or affected component without directly identifying which server hardening control should be reviewed. AI can assist by analysing the text and relating the information to predefined security categories.

For Windows Server hardening, this can be useful when an advisory refers to concepts such as remote access attacks, brute-force attempts, authentication weaknesses, or firewall exposure. The relevant hardening areas may include RDP security, account lockout policy, password policy, firewall configuration, audit policy, or Windows Defender.

However, AI-generated analysis should not be treated as automatically correct. An AI model may misunderstand security context, produce an inaccurate explanation, or associate an advisory with an incorrect security control. Therefore, AI should be used as decision support rather than as the sole authority for security decisions.

<a id="report-section-2-3-1"></a>

#### 2.3.1 Large Language Models

Large Language Models (LLMs) are relevant to cybersecurity tasks that involve processing natural language, such as security advisories, vulnerability descriptions, and technical explanations. Recent research demonstrates that LLMs can support reasoning, tool use, and multi-step problem solving.

For example, the ReAct approach combines reasoning and actions, while Toolformer demonstrates the use of external tools by language models (Yao et al., 2023; Schick et al., 2023). These capabilities are relevant to cybersecurity workflows where an AI system may need to interpret an advisory, analyse system information, and provide a structured recommendation.

In the proposed project, the Local LLM generates human-readable explanations of non-compliant CIS findings using the finding information and stored CIS control rationale. It does not ingest external advisories, map CVEs, or generate executable remediation commands. However, the LLM is restricted to a defined task and does not directly control the Windows Server. This reduces the effect of incorrect AI-generated outputs on the actual system.

<a id="report-section-2-3-2"></a>

#### 2.3.2 Agentic AI

Agentic AI refers to AI systems that can perform goal-oriented tasks through activities such as reasoning, planning, tool use, and interaction with external systems. Unlike a conventional chatbot that mainly produces responses to user prompts, an agentic system can perform a sequence of actions to complete a task. (Guo et al., 2024; Wu et al., 2023)

This approach is relevant to cybersecurity because security assessment is usually a multi-step process involving configuration collection, analysis, vulnerability interpretation, prioritisation, recommendation, and reporting. Agentic AI can divide these activities into separate tasks rather than relying on a single component to perform the entire workflow.

Recent research on LLM-based agents and multi-agent systems demonstrates the potential of specialised agents to cooperate in completing complex tasks (Wu et al., 2023; Malatji, 2025; Shahriar et al., 2025).

For the proposed project, agentic AI provides the conceptual foundation for separating the security workflow into specialised components. The project uses a Scanner Agent, Analysis Agent, and Remediation Agent, coordinated by an AI Agent Orchestrator. However, these agents are part of the proposed system design and are therefore discussed in greater detail in the subsequent system design and implementation chapters.

<a id="report-section-2-3-3"></a>

#### 2.3.3 Multi-Agent Systems

Multi-agent systems consist of multiple agents that cooperate to complete a task. Each agent can be assigned a specific responsibility, allowing a complex workflow to be divided into smaller and more manageable tasks.

This approach is useful for cybersecurity because different stages of a security workflow require different functions. One component may collect configuration information, another may analyse vulnerability information, and another may assist with decision-making or remediation planning. Separating these responsibilities can improve modularity and make the system easier to test and maintain (Wu et al., 2023; Shahriar et al., 2025).

However, multi-agent systems also introduce additional risks. Incorrect output from one agent may affect the decisions made by another agent. Excessive autonomy may also allow an agent to perform actions that are unsuitable for the target environment. Therefore, multi-agent cybersecurity systems require appropriate boundaries, validation, access control, and human oversight. (Shahriar et al., 2025; OWASP Foundation, n.d.)

The proposed framework addresses these concerns by assigning each agent a limited responsibility and keeping remediation under administrator control.

<a id="report-section-2-3-4"></a>

#### 2.3.4 AI-Assisted Vulnerability Analysis

AI-assisted vulnerability analysis involves using AI to interpret, classify, and prioritise vulnerability information. This is particularly useful when vulnerability descriptions do not directly correspond to security configuration controls.

For example, a CVE description may discuss unauthorised remote access or authentication attacks without explicitly stating that an administrator should review a particular Windows Server hardening setting. An LLM can assist in identifying the security concepts in the description and mapping them to predefined hardening categories. (Hasanov et al., 2024)

This approach can provide more contextual analysis than simple keyword matching because similar security concepts may be described using different terminology. However, AI-generated mappings should be validated because incorrect classification may cause the wrong security control to be prioritised.

Although AI-assisted advisory mapping may be useful in broader vulnerability-management systems, it is outside the scope of this project. The proposed framework restricts the Local LLM to explaining non-compliant CIS findings using stored control information.

<a id="report-section-2-3-5"></a>

#### 2.3.5 AI-Assisted Remediation

Security assessment is useful for identifying weaknesses, but administrators also need to understand how those weaknesses can be corrected. AI-assisted remediation can support the generation, selection, or explanation of possible corrective actions.

For Windows Server, remediation may involve changing security policies, enabling firewall settings, configuring audit policies, strengthening authentication settings, or modifying other security configurations. AI can assist by providing explanations or recommending suitable commands.

However, automatic execution of AI-generated commands introduces additional security risks. Incorrect commands may modify the wrong setting, affect required services, or reduce system availability. OWASP guidance highlights risks such as prompt injection, insecure output handling, excessive agency, and unsafe tool use in LLM and AI agent systems (OWASP Foundation, n.d., 2025).

Therefore, AI-assisted remediation should include restrictions such as predefined commands, output validation, limited permissions, and human approval. The proposed framework follows this approach by generating remediation recommendations for administrator review rather than automatically applying changes.

<a id="report-section-2-3-6"></a>

#### 2.3.6 Configuration Drift

Security configurations may change after a system has initially been hardened. Such changes can result from software updates, system maintenance, troubleshooting activities, administrative changes, or human error. These changes may cause a system to deviate from its established secure configuration.

Configuration drift refers to the deviation between an expected configuration state and the current configuration state of a system. Monitoring configuration changes is therefore important because a system that initially satisfies its security requirements may become non-compliant after subsequent changes.

Repeated security assessments can be used to identify such deviations by comparing the current configuration with previously recorded assessment results or established baseline requirements. Historical assessment information can also assist administrators in identifying when a configuration has changed and which security control is affected. (Thiyagarajan et al., 2024)

Within the proposed framework, configuration drift detection is considered as an extension of CIS-based configuration assessment. Changes in the compliance status of selected security controls can be identified through comparison of assessment results over time, allowing administrators to determine whether previously compliant configurations have become non-compliant.

<a id="report-section-2-4"></a>

### 2.4 Research Gap

The reviewed literature demonstrates that several established approaches are available for Windows Server security assessment and cybersecurity decision support. CIS Benchmarks and Microsoft security baselines provide structured recommendations for secure system configurations, while existing security assessment tools support automated configuration and vulnerability assessment. However, these approaches primarily focus on identifying configuration weaknesses or security findings and generally require further interpretation by administrators to determine their relative importance and appropriate remediation. (Center for Internet Security [CIS], 2026; Microsoft, 2026)

Vulnerability prioritisation methods such as CVSS and EPSS provide standardised information regarding vulnerability severity and exploitation likelihood. However, these approaches do not specifically address the relationship between vulnerability information and Windows Server configuration compliance. As a result, a non-compliant configuration may require additional contextual analysis to determine its relevance and priority within a particular system environment. (FIRST, 2023; Jacobs et al., 2023; Agyei et al., 2026)

Recent research on artificial intelligence, Large Language Models, and multi-agent systems demonstrates their potential for natural language analysis, reasoning, task delegation, and cybersecurity decision support. However, existing AI-based approaches are generally broad in scope and are not specifically focused on integrating Windows Server CIS-based configuration assessment and configuration-based risk prioritisation. (Hasanov et al., 2024; Guo et al., 2024; Wu et al., 2023; Shahriar et al., 2025)

AI-assisted remediation also introduces security concerns because inaccurate or inappropriate AI-generated actions may affect system configurations. Existing AI security guidance therefore emphasises controlled tool access, validation, least privilege, and human oversight when AI systems interact with security-sensitive environments (Tabassi, 2023; OWASP Foundation, n.d., 2025).

In addition, configuration drift represents a further challenge because a system that initially satisfies its security requirements may become non-compliant as its configuration changes over time. Although repeated assessment can identify configuration changes, configuration drift detection is not necessarily integrated with AI-assisted vulnerability analysis and security recommendation workflows. (Thiyagarajan et al., 2024)

Therefore, a research gap exists in the integration of CIS-based Windows Server configuration assessment, contextual risk prioritisation, controlled remediation recommendation, and configuration drift detection within a single framework. The proposed Agentic AI Framework addresses this gap by combining these functions within a controlled workflow while maintaining administrator oversight over security-sensitive remediation activities.

**Table 2.2 Summary of Literature and Identified Research Gap**

| Literature Area | Main Finding | Identified Gap | Relevance to Project |
| --- | --- | --- | --- |
| CIS Benchmarks and security baselines | Provide structured secure configuration recommendations | Still require assessment and interpretation | Provides expected secure values |
| Security compliance tools | Can automate configuration and compliance assessment | Mainly focus on scanning and reporting | Supports automated scanning |
| Vulnerability prioritisation | Uses severity, exploitability and other risk indicators | Not directly integrated with Windows Server compliance | Supports risk prioritisation |
| LLMs | Can support reasoning and natural language analysis | May produce inaccurate outputs | Supports human-readable explanation of CIS findings |
| Multi-agent systems | Can divide complex tasks among specialised agents | Require strong control and validation | Supports modular agent architecture |
| AI security and guardrails | Recommend validation, least privilege and human oversight | Unsafe autonomy remains a concern | Supports human-approved remediation |
| Configuration drift | Repeated assessment can identify configuration changes | Often separated from AI-assisted workflows | Supports historical comparison |
| AI security and governance | AI systems can support cybersecurity tasks but require appropriate security controls | Security-sensitive AI operations require validation, controlled access, and human oversight | Supports controlled and human-supervised agent architecture |

Note. Synthesised from Center for Internet Security (2024, 2026), Microsoft (2026), FIRST (2023), Jacobs et al. (2023), Agyei et al. (2026), Hasanov et al. (2024), Guo et al. (2024), Wu et al. (2023), Shahriar et al. (2025), OWASP Foundation (n.d., 2025), and Thiyagarajan et al. (2024).

Chapter 3

Methodology and Requirements Analysis

<a id="report-section-3"></a>

## 3. Methodology and Requirements Analysis

This chapter describes the development methodology and requirements analysis for the proposed Agentic AI Framework for Windows Systems Hardening and CIS Compliance Assessment. It defines the approach used to develop the prototype, the required system functions, operating constraints, selected security controls, and criteria used to define and assess the required system functions.

The framework targets a Windows Server 2022 environment. Its compliance assessment is based on the CIS Microsoft Windows Server 2022 Benchmark v5.1.0, with a selected set of controls within the project scope. The prototype is intended to implement 36  measurable controls across the selected security areas. Each selected control is associated with its CIS benchmark identifier, expected secure configuration, assessment method, and verification information.

The proposed framework consists of three operational agents: the Scanner Agent, Analysis Agent, and Remediation Agent, coordinated by an AI Agent Orchestrator. The Scanner Agent collects Windows Server configuration evidence using permitted read-only functions and evaluates the collected values against predefined compliance rules. The Analysis Agent processes assessment findings and applies the predefined risk-prioritisation method to identify the relative priority of non-compliant controls. The AI Agent Orchestrator identifies applicable remediation actions from the approved remediation library and presents the proposed action for administrator approval. The Remediation Agent executes the approved action after authorisation

The framework combines deterministic security operations with AI-assisted reasoning. Compliance evaluation, numerical risk calculation, command validation, approval enforcement, remediation execution, and verification are performed using predefined or deterministic functions. The local Large Language Model is used only to interpret supporting security information and generate human-readable explanations for non-compliant findings. It does not determine compliance, calculate or modify risk scores, select remediation actions, or influence workflow decisions. The language model does not modify benchmark values, alter calculated risk scores, bypass approval requirements, or determine compliance without verification.

Supporting functions include configuration drift detection, local data storage, and a Streamlit Dashboard. Historical assessment results are stored to support comparison between assessments and identification of configuration changes. The dashboard retrieves stored assessment data and presents compliance results, control status, risk information, and relevant visualisations to the administrator. These supporting functions are not treated as independent agents because they do not independently determine objectives or select the next system action.

The remainder of this chapter presents the development methodology, requirement gathering and analysis, proposed system workflow, use case analysis, and requirement traceability. These requirements provide the basis for the subsequent system implementation and evaluation.

<a id="report-section-3-1"></a>

### 3.1 Development Methodology

The Iterative Prototyping Development Model is adopted for the development of the proposed Agentic AI Framework for Windows Systems Hardening and CIS Compliance Assessment. The model supports the development of a system through successive stages in which individual components can be developed, tested, evaluated, and refined before being integrated into the complete system. This approach is suitable for the proposed project because the framework consists of several interacting components, including the Scanner Agent, Analysis Agent, Remediation Agent, AI Agent Orchestrator, database, configuration drift detection, and dashboard.

The iterative approach also allows technical issues and requirement inconsistencies to be identified at an early stage. For example, the Scanner Agent can first be tested using selected Windows Server security controls before it is integrated with the Analysis Agent and subsequent components. Similarly, the risk-prioritisation mechanism can be evaluated independently before being incorporated into the complete workflow. This reduces the difficulty of identifying the source of errors during full system integration.

The development process is organised into four major phases. The first phase focuses on requirement and benchmark analysis, including the identification of project requirements, system constraints, the selected CIS Microsoft Windows Server 2022 Benchmark v5.1.0, and the security controls included within the project scope. The second phase focuses on prototype development, where the Scanner Agent, Analysis Agent, Remediation Agent, and basic agent coordination are implemented and tested individually.

The third phase focuses on system integration, where the developed components are connected with the supporting database, configuration drift detection, and dashboard. The final phase focuses on testing and refinement, including functional testing, CIS compliance assessment, risk calculation, remediation verification, configuration drift detection, and overall system evaluation.

The iterative development process allows the system to be progressively improved based on the results obtained from each development phase. This approach is consistent with the project plan established in Chapter 1, which specifies progressive development of the selected CIS controls, agents, risk-scoring mechanism, remediation functions, configuration drift detection, dashboard, and final system integration.

**Table 3.1 Development Phases**

| Phase | Main Activities | Expected Outcome |
| --- | --- | --- |
| Phase 1: Requirement and Benchmark Analysis | Define requirements, project scope, selected CIS controls, risk-scoring approach, and system constraints | Defined system scope and requirements |
| Phase 2: Prototype Development | Develop and test Scanner Agent, Analysis Agent, Remediation Agent, and agent coordination | Working individual components |
| Phase 3: System Integration | Integrate agents, database, configuration drift detection, and dashboard | Integrated system prototype |
| Phase 4: Testing and Refinement | Conduct functional, compliance, risk, remediation, drift, and system evaluation testing | Tested and refined final prototype |

<a id="report-section-3-2"></a>

### 3.2 Requirement Gathering and Analysis

Requirement analysis is conducted to identify the functions, constraints, security controls, and system characteristics required by the proposed Agentic AI Framework for Windows Systems Hardening and CIS Compliance Assessment. The requirements are derived from the project objectives, the selected CIS Microsoft Windows Server 2022 Benchmark v5.1.0, relevant security guidance, supervisor consultation, and observations obtained during system development.

The project objectives are translated into specific system requirements. The objective of assessing Windows Server security configurations is addressed through requirements for configuration evidence collection, expected-value comparison, and compliance evaluation. The objective of prioritising non-compliant controls is addressed through requirements for predefined risk factors, deterministic risk calculation, risk classification, and prioritisation. The objectives related to remediation and configuration comparison are addressed through controlled remediation, verification, historical assessment storage, and comparison of assessment results.

Supervisor consultation is used to refine the project scope, system functions, agent responsibilities, and security requirements. The consultation helps ensure that the proposed framework remains consistent with the defined project objectives and that the implemented functions can be evaluated using measurable results.

During development, prototype observations are also used to identify technical requirements and implementation issues. These observations may include unsupported PowerShell commands, inconsistent configuration values, permission requirements, output formatting issues, and verification problems. Identified issues are used to refine the corresponding system functions and requirements.

The requirements are organised into functional requirements, non-functional requirements, and system and technical requirements. Functional requirements define the operations that the framework must perform, while non-functional requirements define the expected qualities and constraints of the system. System and technical requirements specify the hardware, software, operating environment, and supporting resources required for implementation.

The resulting requirements provide the basis for defining the system scope, selected CIS controls, system architecture, risk-prioritisation method, implementation, and subsequent evaluation.

<a id="report-section-3-2-1"></a>

#### 3.2.1 System Scope and Assumptions

The proposed framework is developed for a Windows Server 2022 environment and focuses on assessing selected Windows Server security configurations against the CIS Microsoft Windows Server 2022 Benchmark v5.1.0. The project does not attempt to implement the complete CIS Benchmark. Instead, a selected set of controls is included according to the defined project scope, with 36 measurable security controls included within the project scope.

The framework consists of three operational agents: the Scanner Agent, Analysis Agent, and Remediation Agent, coordinated by an AI Agent Orchestrator. The Scanner Agent collects and assesses selected Windows Server configuration settings. The Analysis Agent processes non-compliant findings and applies the predefined risk-prioritisation method. The AI Agent Orchestrator identifies applicable remediation actions from the approved remediation library and presents the proposed action for administrator approval. The Remediation Agent executes the approved action after authorisation.

The framework assumes that the target Windows Server environment provides the permissions required to perform the defined configuration checks and approved remediation actions. The assessment is limited to the security controls included in the project scope and does not represent a complete assessment of all Windows Server security settings.

The framework uses a local Large Language Model (LLM) to support selected analysis and reasoning tasks. The LLM is not responsible for determining compliance results or calculating numerical risk scores. These security decisions are performed using predefined and deterministic rules. Remediation actions are also subject to administrator approval before execution.

The implementation integrates CIS-based configuration assessment, risk prioritisation, controlled remediation, configuration comparison, and dashboard presentation within the defined project scope.

<a id="report-section-3-2-2"></a>

#### 3.2.2 CIS Benchmark and Control Scope

The proposed framework uses the CIS Microsoft Windows Server 2022 Benchmark v5.1.0 as the reference baseline for Windows Server security configuration assessment. The benchmark provides recommended security configurations for Windows Server 2022 and assigns an identifier to each security recommendation. These identifiers and recommended values provide a consistent basis for determining whether the assessed configuration complies with the selected security requirements (Center for Internet Security [CIS], 2026).

The project does not implement all controls contained in the benchmark. Instead, a selected set of controls is defined according to the project scope and implementation feasibility. The selected controls focus on five security areas: Account Policies, Local Security Options, Windows Defender Firewall, Advanced Audit Policy, and Remote Desktop Services. A total of 36 controls are defined for the project and selected for implementation.

Each selected control is represented as a predefined security requirement within the system. The control record contains the relevant CIS control identifier, security area, control name, expected secure configuration, assessment method, and verification information. The expected secure configuration is used as the reference value when the Scanner Agent evaluates the corresponding Windows Server setting.

The selected controls and their corresponding CIS Benchmark references are presented in Table 3.2.

**Table 3.2 Selected CIS Windows Server 2022 Security Controls**

| No. | Security Area | Selected CIS Control | CIS Benchmark Reference |
| --- | --- | --- | --- |
| 1 | Account Policies | Enforce password history | 1.1.1 |
| 2 | Account Policies | Maximum password age | 1.1.2 |
| 3 | Account Policies | Minimum password age | 1.1.3 |
| 4 | Account Policies | Minimum password length | 1.1.4 |
| 5 | Account Policies | Password complexity requirements | 1.1.5 |
| 6 | Account Policies | Reversible password encryption | 1.1.7 |
| 7 | Account Policies | Account lockout duration | 1.2.1 |
| 8 | Account Policies | Account lockout threshold | 1.2.2 |
| 9 | Account Policies | Reset account lockout counter | 1.2.4 |
| 10 | Account Policies | Administrator account lockout setting | 1.2.3 |
| 11 | Local Security Options | Guest account status | 2.3.1.1 |
| 12 | Local Security Options | Built-in Administrator account name | 2.3.1.3 |
| 13 | Local Security Options | Built-in Guest account name | 2.3.1.4 |
| 14 | Local Security Options | Local accounts with blank passwords | 2.3.1.2 |
| 15 | Local Security Options | Anonymous SID/name translation | 2.3.10.1 |
| 16 | Local Security Options | Anonymous enumeration of SAM accounts | 2.3.10.2 |
| 17 | Local Security Options | Anonymous enumeration of SAM accounts and shares | 2.3.10.3 |
| 18 | Windows Defender Firewall | Domain firewall profile | 9.1.1 |
| 19 | Windows Defender Firewall | Private firewall profile | 9.2.1 |
| 20 | Windows Defender Firewall | Public firewall profile | 9.3.1 |
| 21 | Windows Defender Firewall | Domain profile default inbound connections | 9.1.2 |
| 22 | Windows Defender Firewall | Private profile default inbound connections | 9.2.2 |
| 23 | Windows Defender Firewall | Public profile default inbound connections | 9.3.2 |
| 24 | Windows Defender Firewall | Domain profile dropped-packet logging | 9.1.6 |
| 25 | Windows Defender Firewall | Private profile dropped-packet logging | 9.2.6 |
| 26 | Windows Defender Firewall | Public profile dropped-packet logging | 9.3.8 |
| 27 | Advanced Audit Policy | Credential validation auditing | 17.1.1 |
| 28 | Advanced Audit Policy | Account lockout auditing | 17.5.1 |
| 29 | Advanced Audit Policy | User account management auditing | 17.2.6 |
| 30 | Advanced Audit Policy | Security group management auditing | 17.2.5 |
| 31 | Advanced Audit Policy | Logon auditing | 17.5.4 |
| 32 | Remote Desktop Services | Network Level Authentication | 18.10.57.3.9.4 |
| 33 | Remote Desktop Services | RDP security layer | 18.10.57.3.9.3 |
| 34 | Remote Desktop Services | RDP connection encryption level | 18.10.57.3.9.5 |
| 35 | Remote Desktop Services | Prompt for password upon connection | 18.10.57.3.9.1 |
| 36 | Remote Desktop Services | Saving passwords for Remote Desktop connections | 18.10.57.2.2 |

The selected controls provide coverage across account security, local security configuration, network protection, security auditing, and remote access. During assessment, each control is evaluated independently according to its predefined expected configuration. A control is classified as compliant when the observed configuration satisfies the corresponding requirement; otherwise, it is classified as non-compliant and is passed to the Analysis Agent for risk prioritisation.

<a id="report-section-3-2-3"></a>

#### 3.2.3 Functional Requirements

The functional requirements define the operations that the proposed framework shall perform to support Windows Server security configuration assessment, risk prioritisation, controlled remediation, configuration monitoring, and dashboard presentation. The requirements are derived from the project objectives, selected CIS controls, and the defined system scope.

**Table 3.3 Functional Requirements**

| ID | Functional Requirement |
| --- | --- |
| FR01 | The system shall collect the required Windows Server configuration values for the selected CIS security controls. |
| FR02 | The system shall compare the collected configuration values with the predefined expected secure configurations for the selected CIS controls. |
| FR03 | The system shall classify each assessed CIS control as compliant or non-compliant based on the assessment result. |
| FR04 | The system shall record the observed configuration, expected configuration, compliance status, and assessment information for each assessed control. |
| FR05 | The system shall pass non-compliant findings to the Analysis Agent for risk prioritisation. |
| FR06 | The system shall calculate a risk score for non-compliant findings using the predefined risk-prioritisation method. |
| FR07 | The system shall classify and prioritise non-compliant findings according to their calculated risk levels. |
| FR08 | The system shall provide remediation recommendations from the approved remediation library for the defined subset of remediable non-compliant controls. |
| FR09 | The system shall require administrator approval before executing configuration-changing remediation actions. |
| FR10 | The system shall execute an administrator-approved remediation action for an applicable control within the defined remediable-control subset. |
| FR11 | The system shall reassess the affected security control after remediation using its predefined compliance criteria to determine whether the expected secure configuration has been achieved. |
| FR12 | The system shall store assessment results, risk information, remediation results, verification results, and configuration drift records in the local database. |
| FR13 | The system shall compare current assessment results with previous comparable assessment results to identify configuration changes. |
| FR14 | The system shall provide dashboard views of compliance results, risk priorities, remediation status, verification results, configuration drift, and historical assessment information. |
| FR15 | The system shall allow administrators to review assessment findings and remediation information before approving configuration changes. |
| FR16 | The system shall use the AI Agent Orchestrator to coordinate the Scanner Agent, Analysis Agent, and Remediation Agent according to the current assessment and hardening workflow state. |
| FR17 | The system shall provide human-readable explanations for non-compliant security findings to support administrator review and understanding. |

The functional requirements establish the main operations of the proposed framework. The requirements begin with configuration assessment and compliance evaluation, followed by risk prioritisation of non-compliant findings. Remediation recommendations and administrator approval are then used to control configuration changes, while post-remediation verification confirms the resulting configuration. Assessment and remediation information is stored for historical comparison and presented through the dashboard.

<a id="report-section-3-2-4"></a>

#### 3.2.4 Non-Functional Requirements

Non-functional requirements define the quality attributes and operational constraints that the proposed framework should satisfy. The requirements focus on security, reliability, usability, performance, and maintainability of the system.

**Table 3.4 Non-Functional Requirements**

| ID | Non-Functional Requirement |
| --- | --- |
| NFR01 | The system shall restrict configuration-changing operations to approved remediation actions and require administrator approval before execution. |
| NFR02 | The system shall maintain consistent assessment results by applying predefined compliance and risk-prioritisation rules. |
| NFR03 | The system shall present compliance status, risk level, remediation status, and verification outcomes through clearly labelled dashboard views that support administrator review without requiring interpretation of raw database records. |
| NFR04 | The system shall maintain assessment, risk, remediation, verification, and configuration history records in a structured local database to support reliable retrieval and comparison. |
| NFR05 | The system shall use a modular design that allows the Scanner Agent, Analysis Agent, Remediation Agent, and supporting components to be maintained independently. |
| NFR06 | The system shall perform configuration assessment and verification within 10 minutes for the selected Windows Server controls and project environment. |
| NFR07 | The Local LLM shall be restricted to supporting interpretation and explanation tasks and shall not directly execute configuration-changing actions or determine numerical risk scores. |
| NFR08 | The system shall process Windows Server configuration data locally and shall not require an external cloud service for assessment, risk calculation, or explanation generation. |

These requirements establish the operational qualities and constraints of the proposed framework. Security and consistency are addressed through controlled remediation and predefined assessment and risk rules. Usability is supported through clear presentation of assessment and remediation information, while maintainability is supported through the modular structure of the framework. The system is designed to operate within the technical environment defined for the project.

<a id="report-section-3-2-5"></a>

#### 3.2.5 System and Technical Requirements

The system and technical requirements define the software, hardware, and operating environment required to develop and operate the proposed framework. The requirements are based on the selected Windows Server environment and the technologies used to implement the system.

**Table 3.5 System and Technical Requirements**

| ID | Requirement |
| --- | --- |
| STR01 | The system shall operate on a Windows Server 2022 environment for security configuration assessment and remediation. |
| STR02 | The system shall use PowerShell to collect Windows Server configuration information and perform approved configuration changes. |
| STR03 | The system shall use Python as the primary programming language for the framework and agent workflow. |
| STR04 | The system shall use a local Large Language Model (LLM) to support interpretation and human-readable explanations for non-compliant findings. |
| STR05 | The system shall use a local database to store assessment results, risk scores, remediation records, verification results, and historical assessment data. |
| STR06 | The system shall provide a web-based dashboard for displaying compliance and assessment information. |
| STR07 | The system shall require sufficient system resources to run the Windows Server environment, application components, local database, and local LLM within the project environment. |

The identified requirements establish the technical environment required by the proposed framework. Windows Server 2022 provides the target environment, while PowerShell is used for Windows configuration assessment and approved remediation. Python provides the main application and agent workflow implementation. A local LLM supports selected AI-assisted tasks, while the local database stores assessment and historical information. The dashboard provides a user interface for reviewing the resulting security information.

Ollama is used as the local model-serving platform because it provides a local API through which the Python-based framework can send prompts and receive responses (Ollama, n.d.). Qwen3-8B is selected as the locally deployable model for generating supporting explanations for non-compliant findings (Qwen Team, n.d.).

<a id="report-section-3-3"></a>

### 3.3 Proposed System Workflow

The proposed framework follows an integrated workflow for assessing Windows Server security configurations against the selected CIS security controls, analysing non-compliant findings, and supporting controlled remediation. The workflow begins when the administrator initiates a security assessment. The AI Agent Orchestrator coordinates the subsequent activities and directs the appropriate agent according to the current workflow state.

The Scanner Agent first collects the required Windows Server configuration information using the defined assessment functions. The collected values are then compared with the predefined expected secure configurations associated with the selected CIS controls. Each control is classified as compliant or non-compliant based on the assessment result. Compliant findings are recorded, while non-compliant findings are forwarded to the Analysis Agent for further assessment.

The Analysis Agent evaluates the non-compliant findings and applies the predefined risk-prioritisation method to determine their relative risk and priority. The Analysis Agent applies the predefined risk-prioritisation rules and requests a human-readable explanation from the Local LLM using the finding information and the stored CIS control rationale. The resulting risk information is recorded and used to determine whether remediation should be recommended.

For applicable findings, the AI Agent Orchestrator identifies the corresponding remediation action from the approved remediation library and presents the proposed action to the Administrator for review. If approved, the Orchestrator delegates the remediation task to the Remediation Agent.

Following remediation, the affected configuration is assessed again to verify whether the required security setting has been successfully applied. The resulting assessment, risk, remediation, and verification information is stored in the local database. The dashboard then retrieves the stored information to present the compliance status, prioritised findings, remediation results, and relevant assessment history to the administrator.

The overall workflow therefore follows the sequence of assessment, compliance evaluation, analysis, risk prioritisation, remediation recommendation, administrator approval, remediation execution, verification, and result recording. This workflow provides a structured connection between the selected CIS security requirements and the security assessment and remediation functions of the proposed framework.

The data flow between the assessment process, database, and dashboard can be summarised as:

Assessment and Analysis > Database > Dashboard > Administrator Review

<a id="report-section-3-4"></a>

### 3.4 Use Case Analysis

Use case analysis is used to identify the main actors and interactions required to support the operation of the proposed framework. The identified use cases are derived from the functional requirements and represent the activities that administrators and system components perform during security assessment, risk prioritisation, remediation, verification, and result review.

**Table 3.6 Main Actors and Responsibilities**

| Actor | Main Responsibilities |
| --- | --- |
| Administrator | Initiates security assessments, reviews compliance and risk findings, reviews proposed remediation actions, approves or rejects configuration changes, and reviews results through the dashboard. |
| AI Agent Orchestrator | Coordinates the overall workflow and delegates appropriate tasks to the operational agents according to the current workflow state. |
| Scanner Agent | Collects Windows Server configuration information and evaluates the selected CIS controls. |
| Analysis Agent | Analyses non-compliant findings, applies the predefined risk-prioritisation method, and provides relevant security explanations. |
| Remediation Agent | Executes administrator-approved configuration changes and performs post-remediation verification. |
| Local Database | Stores assessment, risk, remediation, verification, and historical information required by the framework. |

The principal use cases of the framework are shown in Table 3.7.

**Table 3.7 Main Use Cases**

| Use Case | Description |
| --- | --- |
| UC01 - Perform Security Assessment | The Administrator initiates an assessment, after which the Scanner Agent collects the required Windows Server configuration values and evaluates the selected CIS controls. |
| UC02 - Analyse Non-Compliant Findings | Non-compliant findings are passed to the Analysis Agent for risk prioritisation and security analysis. |
| UC03 - Calculate and Prioritise Risk | The predefined risk-prioritisation method is applied to the relevant findings to calculate risk scores and assign risk levels. |
| UC04 - Review Remediation | The Administrator reviews the identified finding, risk information, and proposed remediation action. |
| UC05 - Approve and Execute Remediation | The Administrator approves an applicable remediation action, after which the Remediation Agent executes the corresponding predefined configuration change. |
| UC06 - Verify Remediation | The framework reassesses the affected configuration after remediation and determines whether the required security configuration has been achieved. |
| UC07 - Detect Configuration Drift | The framework compares the current assessment with a previous comparable assessment to identify changes in selected security configurations. |
| UC08 - View Dashboard | The Administrator uses the Streamlit dashboard to review compliance percentage, control status, risk information, remediation results, verification results, and assessment history. |

Use Case match to Functional Requirements:

UC01 > FR01, FR02, FR03, FR04

UC02/UC03 > FR05, FR06, FR07

UC04/UC05 > FR08, FR09, FR10, FR15

UC06 > FR11

UC07 > FR13

UC08 > FR12, FR14

The identified use cases represent the principal interactions required by the framework. The Administrator remains responsible for initiating assessments, reviewing findings, and approving configuration-changing actions, while the operational agents perform their respective security assessment, analysis, remediation, and verification functions. The AI Agent Orchestrator coordinates these activities to maintain the defined assessment and hardening workflow.

<a id="report-section-3-5"></a>

### 3.5 Requirement Traceability

Requirement traceability is used to establish the relationship between the project objectives and the functional requirements of the proposed framework. The traceability ensures that the functional requirements defined in Section 3.2.3 are aligned with the objectives of the project and provide a measurable basis for subsequent system design, implementation, and evaluation.

The relationship between the project objectives and the functional requirements is presented in Table 3.8.

**Table 3.8 Requirement Traceability**

| Objective | Related Functional Requirements |
| --- | --- |
| Objective 1: Develop a Scanner Agent to automatically collect and assess Windows Server security configurations against selected CIS-aligned controls. | FR01, FR02, FR03, FR04 |
| Objective 2: Develop an Analysis Agent to identify and prioritise non-compliant security controls using the predefined risk-scoring method and provide understandable explanations. | FR05, FR06, FR07, FR17 |
| Objective 3: To develop a Remediation Agent that provides controlled remediation actions for a defined subset of selected controls using a pre-approved PowerShell library, with administrator approval required before configuration-changing actions are executed. | FR08, FR09, FR10, FR15 |
| Objective 4: Develop an AI Agent Orchestrator to coordinate the specialised agents and manage the assessment and hardening workflow. | FR16 |
| Objective 5: Implement post-remediation verification to determine whether an approved remediation action successfully changes the affected control to the expected configuration. | FR11 |
| Objective 6: Implement configuration drift detection and historical storage to identify changes in Windows Server security configurations across assessments. | FR12, FR13 |
| Objective 7: To develop a Streamlit-based dashboard that presents compliance results, risk priorities, remediation status, verification results, configuration drift, and historical assessment information. | FR14 |

The traceability matrix provides a direct connection between the project objectives and the functional requirements defined in Section 3.2.3. Each objective is associated with one or more functional requirements that define the measurable system behaviour required to achieve the corresponding objective. This traceability provides a basis for subsequent system design, implementation, and evaluation by allowing the implemented functions to be assessed against the defined requirements.

Chapter 4

System Design

<a id="report-section-4"></a>

## 4. System Design

This chapter presents the system design of the proposed Windows Server security assessment and hardening framework. The design is developed based on the system requirements, workflow, agent responsibilities, risk-prioritisation method, remediation process, and data management approach defined in Chapter 3.

The chapter describes the overall system architecture and interactions between the Administrator, Streamlit dashboard, AI Agent Orchestrator, specialised agents, Windows Server, local LLM, and database. The agent workflow, system states, software modules, database structure, core security processes, and user interface design are also presented. The diagrams and design specifications in this chapter represent the proposed system structure and processes to be implemented during the subsequent development phases.

<a id="report-section-4-1"></a>

### 4.1 System Architecture

The proposed framework adopts a modular agent-based architecture consisting of the Administrator interface, application and agent components, supporting services, and the Windows Server target environment. The architecture is designed to separate user interaction, agent coordination, security assessment and remediation functions, data storage, and AI-assisted analysis.

The Administrator interacts with the framework through the Streamlit Dashboard, which provides access to assessment results, risk information, remediation status, verification results, and configuration history. The dashboard communicates with the AI Agent Orchestrator, which coordinates the Scanner Agent, Analysis Agent, and Remediation Agent according to the current workflow.

The Scanner Agent is responsible for collecting Windows Server configuration information through PowerShell and performing the selected CIS control assessments. The Analysis Agent processes non-compliant findings and supports risk prioritisation and security-related interpretation. The Remediation Agent manages approved configuration changes and performs post-remediation verification. A local LLM supports selected analysis and reasoning tasks, while deterministic security functions such as compliance comparison and numerical risk calculation remain governed by predefined rules.

The local database provides persistent storage for assessment results, risk records, remediation and verification information, and configuration history. The Windows Server 2022 environment serves as the target system on which the selected security configurations are assessed and, following administrator approval, modified through controlled remediation actions.

<a id="report-section-4-1-1"></a>

#### 4.1.1 Architecture Overview Diagram

*Source image 2 (`word/media/image4.jpg`): retained in the [original DOCX](<C:/Users/User/Downloads/RIS_KhooTengYi_Report.docx>); pixels are not embedded in this text transcription.*

**Figure 4.1 Architecture Overview of the Proposed Windows Server Security Assessment and Hardening Framework**

**Table 4.1 Architecture Components and Role**

Component

Role

Administrator

Initiates assessments, reviews findings, and approves or rejects configuration-changing remediation actions.

Streamlit Dashboard

Provides the user interface for initiating workflows and reviewing assessment, risk, remediation, verification, and historical information.

AI Agent Orchestrator

Coordinates the specialised agents and manages the overall workflow between assessment, analysis, remediation, and verification.

Scanner Agent

Collects Windows Server configuration values through PowerShell and evaluates the selected CIS controls.

Analysis Agent

Processes non-compliant findings and supports risk prioritisation and security-related analysis.

Remediation Agent

Executes approved remediation actions and performs post-remediation verification.

Local LLM

(Ollama / Qwen3-8B)

Supports selected AI-assisted interpretation, reasoning, and explanation tasks.

Local Database

Stores assessment, risk, remediation, verification, and historical configuration information.

Windows Server 2022

Target environment where the selected security configurations are assessed and hardened.

PowerShell

Provides the controlled mechanism for collecting configuration values, executing approved changes, and performing verification.

<a id="report-section-4-1-2"></a>

#### 4.1.2 Local LLM Selection and Boundaries

Why a Local LLM is Used

The proposed framework uses a locally hosted Large Language Model rather than a cloud-based AI service. Windows Server configuration data collected by the Scanner Agent, including account policies, firewall rules, audit settings, and Remote Desktop configurations, can reveal specific details about an organisation’s security posture. Transmitting this information to an external, internet-connected AI service would introduce an additional data exposure risk that is inconsistent with the security objectives of the project. Running the model locally allows the interpretation and explanation function of the Analysis Agent to operate entirely within the boundary of the assessed environment, without any assessment data leaving the local system.

Why Ollama is Selected

Ollama is used as the platform for running the Local LLM. Ollama provides a straightforward mechanism for downloading, running, and serving open-weight language models on a local machine through a local API, which allows the Python-based framework to send prompts to the model and receive responses without requiring a separately managed inference server. This is consistent with the technical feasibility discussed in Section 1.5.1, where a local LLM was identified as a component that could be integrated into the Python application logic without introducing significant infrastructure overhead (Ollama, n.d.).

Why Qwen3-8B is Selected

Qwen3-8B was selected as it was readily available through Ollama at the time the framework’s AI-assisted component was set up, and its 8-billion-parameter size represented a practical balance between local deployability and text-interpretation capability. As development hardware for this project is limited to a laptop-class GPU (NVIDIA GeForce RTX 3050, 4GB VRAM), preliminary testing was carried out to confirm that the selected model could be operated within this environment at an acceptable response time (Qwen Team, n.d.).

During preliminary local testing on the development hardware, a representative finding explanation required approximately 100-110 seconds when reasoning was enabled and approximately 12 seconds when reasoning was disabled. The measurement procedure and performance evaluation will be reported in Chapter 5. Investigation using Ollama's verbose output identified that Qwen3 models generate an internal reasoning sequence by default before producing a final answer, and that this reasoning sequence accounted for the majority of the generated tokens and response time. As the framework’s use of the Local LLM is limited to short, single-finding explanations rather than complex multi-step reasoning, this internal reasoning step was determined to be unnecessary for the intended use case. Disabling this behaviour (think=false) reduced the response time for a representative finding explanation to approximately 12 seconds, without a corresponding change in the underlying token generation rate, confirming that the improvement was attributable to the removal of unneeded reasoning tokens rather than a change in model performance. This response time was assessed as acceptable for the framework’s intended use, where explanations are generated as part of a background analysis step rather than in response to real-time user interaction. On this basis, Qwen3-8B was retained as the selected model, with the reasoning behaviour disabled for all explanation requests issued by the LocalLLMClient component.

What the Local LLM May Do

Within the proposed framework, the Local LLM is restricted to a supporting interpretive role. Specifically, the Local LLM may:

Interpret supporting security information relevant to a non-compliant finding

Generate a human-readable explanation of an assessment result

Assist the Analysis Agent in providing security context for a finding

What the Local LLM Must Not Do

Consistent with the design principle established in Section 2.3.5 and NFR07, the Local LLM must not:

Directly execute PowerShell commands or interact with the Windows Server

Determine or modify the final numerical risk score

Generate or select remediation actions for execution

Bypass the administrator approval requirement defined in FR09

Perform or influence compliance determination

This restriction is reflected in the Class/Module Diagram presented in Section 4.4.1, where LocalLLMClient is connected only to AnalysisAgent through a single generateExplanation() method and has no relationship with RemediationAgent or any component capable of modifying the Windows Server. Numerical risk calculation is handled exclusively by the deterministic RiskEngine class, and remediation actions are drawn only from the approved remediation actions required by NFR01. This separation ensures that the Local LLM functions purely as a supporting interpretive component, with all security-critical decisions remaining deterministic and outside its control.

Local LLM Fallback

If the Local LLM is unavailable, the framework shall continue to perform assessment, risk calculation, remediation control, verification, and history comparison. Only the generated explanation is unavailable.

<a id="report-section-4-2"></a>

### 4.2 Use Case Diagram

*Source image 3 (`word/media/image6.jpg`): retained in the [original DOCX](<C:/Users/User/Downloads/RIS_KhooTengYi_Report.docx>); pixels are not embedded in this text transcription.*

**Figure 4.2: Use Case Diagram of the Proposed Framework**

The use case diagram illustrates the interactions between the Administrator and the proposed Agentic AI Framework for Windows Systems Hardening and CIS Compliance Assessment. The Administrator is the primary actor who initiates security assessments, reviews assessment and risk information, evaluates remediation recommendations, approves or rejects remediation actions, and reviews verification and configuration history through the system dashboard. The internal agents and supporting components are not represented as actors because they operate as internal components of the framework and their interactions are described in the subsequent agent workflow design.

<a id="report-section-4-2-1"></a>

#### 4.2.1 Use Case Description

**Table 4.2 Use Case Description**

Use Case

Actor

Description

Initiate Security Assessment

Administrator

Starts a security assessment of the selected Windows Server CIS controls.

View Compliance Results

Administrator

Reviews the compliance status and configuration results of the assessed controls.

View Risk Priorities

Administrator

Reviews the calculated risk scores and risk levels assigned to non-compliant findings.

Review Remediation Recommendation

Administrator

Reviews the recommended remediation action for an identified non-compliant control.

Approve or Reject Remediation

Administrator

Approves or rejects a proposed configuration-changing remediation action before execution.

View Verification Results

Administrator

Reviews whether the remediated configuration satisfies the expected security requirement after verification.

View Configuration Drifts

Administrator

Reviews changes between current and previous assessment results.

View Dashboard

Administrator

Reviews the overall security status, compliance summary, risk information, and historical assessment information through the dashboard.

<a id="report-section-4-3"></a>

### 4.3 Agent Workflow Design

The agent workflow design defines how the AI Agent Orchestrator coordinates the specialised agents throughout the Windows Server security assessment and hardening process. The workflow separates the major activities into scanning, analysis, risk prioritisation, administrator approval, remediation, and verification. This separation allows each agent to perform a specific responsibility while the Orchestrator manages the overall progression of the assessment. The workflow also maintains administrator involvement before configuration-changing remediation actions are executed.

<a id="report-section-4-3-1"></a>

#### 4.3.1 Agent Sequence Diagram

*Source image 4 (`word/media/image19.jpg`): retained in the [original DOCX](<C:/Users/User/Downloads/RIS_KhooTengYi_Report.docx>); pixels are not embedded in this text transcription.*

**Figure 4.3 Agent Sequence Diagram**

The Agent Sequence Diagram (Figure 4.3) illustrates the message exchange between system components during a single assessment cycle. The Administrator initiates the process through the Streamlit Dashboard, which forwards the request to the AI Agent Orchestrator. The Orchestrator delegates the assessment task to the Scanner Agent, which collects configuration evidence from the Windows Server using PowerShell and stores the resulting compliance findings in the database.

Non-compliant findings are then delegated to the Analysis Agent, which retrieves the fixed I, P, and L baseline scores, uses the local LLM to obtain supporting security interpretation, and deterministically determines the Exposure (E) and Configuration State or Drift (D) factors before applying the risk-scoring formula described in Section 4.6.2.4. The resulting prioritised findings are returned to the Orchestrator, which forwards a proposed remediation action to the Administrator through the dashboard for review. Only after the Administrator's decision is returned does the Orchestrator delegate the task to the Remediation Agent; the Remediation Agent has no independent authority to act before this point. If approved, the Remediation Agent executes the change, re-assesses the affected control, and records the verification outcome; if rejected, the decision is recorded without any configuration change being made.

<a id="report-section-4-3-2"></a>

#### 4.3.2 Orchestrator State Chart

*Source image 5 (`word/media/image14.jpg`): retained in the [original DOCX](<C:/Users/User/Downloads/RIS_KhooTengYi_Report.docx>); pixels are not embedded in this text transcription.*

**Figure 4.4 Orchestrator State Chart**

The Orchestrator State Chart (Figure 4.4) formalises the internal workflow states maintained by the AI Agent Orchestrator. The workflow begins in the Idle state and moves to Assessment Requested once the Administrator initiates an assessment through the dashboard. The Orchestrator then progresses through Scanning, Analysis, and Risk Prioritisation to evaluate the selected CIS controls and calculate their risk scores.

Where a remediation action is applicable, the workflow enters Awaiting Approval, reflecting the mandatory human-in-the-loop checkpoint required by NFR01 and FR09. An approved action moves the workflow to Remediation and then Verification. If verification passes, the workflow reaches Assessment Completed. If verification fails, the workflow does not automatically retry the remediation; instead, it transitions to Remediation Review, after which any further action must again pass through Awaiting Approval before execution. This design prevents the system from repeatedly modifying the Windows Server configuration without administrator oversight, reinforcing the controlled-remediation constraints defined by NFR01 and FR09.

A Failed state also exists to capture configuration collection errors during scanning, from which the workflow returns to Idle after the Administrator is notified. Every terminal path, whether reached through a rejected action, a finding with no applicable remediation, or a successfully verified control, converges on Assessment Completed, which transitions to the final state, marking the end of that assessment cycle.

<a id="report-section-4-4"></a>

### 4.4 Module and Class Design

This section presents the module and class structure planned for the proposed Agentic AI Framework. In accordance with the Iterative Prototyping Development Model adopted in Section 3.1, the structure presented here represents the intended software design derived from the agent responsibilities, functional requirements, and workflow behaviour established in Chapter 3. This design forms the basis for the Prototype Development and System Integration phases and will be implemented and validated in Chapter 5, where any deviations from this design will be documented and explained.

<a id="report-section-4-4-1"></a>

#### 4.4.1 Class/Module Diagram

*Source image 6 (`word/media/image16.jpg`): retained in the [original DOCX](<C:/Users/User/Downloads/RIS_KhooTengYi_Report.docx>); pixels are not embedded in this text transcription.*

**Figure 4.5 Module Class Diagram**

The Class/Module Diagram (Figure 4.5) illustrates the planned internal structure of the framework, showing the responsibilities of each component and the relationships between them. The design separates the framework into five functional layers: a presentation layer, an orchestration layer, an agent layer, a supporting reasoning and calculation layer, and a data layer.

Presentation Layer

The StreamlitDashboard module represents the user-facing component of the framework. It is responsible for initiating an assessment on behalf of the Administrator and for retrieving and displaying compliance results, risk information, remediation status, and historical data from the database. To preserve the separation between presentation and operational responsibilities, StreamlitDashboard has no direct relationship with any of the operational agents; it interacts only with the AIAgentOrchestrator to initiate the workflow and the DatabaseManager to retrieve stored information.

Orchestration Layer

The AIAgentOrchestrator class is the central coordinating component of the framework. It maintains the current workflow state and delegates tasks to the Scanner Agent, Analysis Agent, and Remediation Agent according to the orchestration cycle described in Section 4.3.2. The relationship between StreamlitDashboard and AIAgentOrchestrator is intentionally labelled initiates workflow rather than delegates, since the Dashboard is a user interface module rather than an agent that receives and executes an assigned task. The Orchestrator's relationships with the three operational agents are labelled delegates, reflecting its role in directing the assessment and remediation workflow.

Agent Layer

The ScannerAgent, AnalysisAgent, and RemediationAgent classes correspond to the three operational agents defined in Section 4.1.

ScannerAgent is responsible for collecting Windows Server configuration information and evaluating it against the selected CIS controls. It maintains a relationship with CISControl, representing the expected configuration values used during compliance evaluation, and stores its results through the DatabaseManager.

AnalysisAgent is responsible for processing non-compliant findings. It maintains a relationship with RiskEngine to obtain a deterministic risk score, and a dependency relationship with LocalLLMClient to obtain supporting interpretation and explanation of a finding. Its results are also stored through the DatabaseManager.

Following the Orchestrator’s proposal of an applicable action and its approval by the Administrator, RemediationAgent is responsible for executing an approved remediation action from the pre-approved PowerShell library and for triggering post-remediation verification. Consistent with NFR01, RemediationAgent has no relationship with LocalLLMClient, since remediation actions are predefined rather than generated by the language model. This separation prevents the LLM from directly producing configuration-changing commands.

Supporting Reasoning and Calculation Layer

The RiskEngine class performs the deterministic risk-scoring calculation described in Section 4.6.2.4, taking the five risk factors (Security Impact, Exposure, Privilege Impact, Likelihood, and Configuration State or Drift) as input and returning a numerical risk score and corresponding risk level.

The LocalLLMClient class represents a wrapper around the local language model and is limited to generating explanations from a supplied prompt. The separation of RiskEngine from AnalysisAgent, and the absence of any risk-calculating or command-generating method within LocalLLMClient, reflects the constraint defined by NFR07: numerical risk calculation and remediation actions remain deterministic and outside the control of the language model, which is restricted to interpretation and explanation.

Data Layer

The CISControl class is a data-oriented class representing a single selected CIS control, including its identifier, security area, expected configuration value, and benchmark reference, corresponding to the control catalogue defined in Table 3.2. The DatabaseManager class provides the interface through which the Scanner Agent, Analysis Agent, and Remediation Agent store their respective results, and through which the Streamlit Dashboard retrieves data for display. This produces a clear separation between components that write assessment data and the single component that reads it for presentation, consistent with the data flow described in Section 4.5.3.

Design Rationale

The overall structure reflects three design decisions underlying the framework. First, the Orchestrator coordinates the workflow but does not itself perform assessment, analysis, or remediation, preserving the separation of responsibilities shown in Section 4.1. Second, the language model is represented as a supporting dependency of the Analysis Agent only, with no direct access to configuration-changing functions, reflecting the controlled use of AI described in Section 2.3.5 and the controlled-remediation constraint defined by NFR01. Third, all persistent data flows through a single DatabaseManager component, providing a consistent record of assessment, risk, remediation, and verification information as required by FR12.

Although security-critical operations are implemented using deterministic functions, this does not remove the agentic characteristics of the framework. The specialised agents operate toward defined objectives, invoke permitted functions, observe the results returned by those functions, and coordinate subsequent workflow actions through the AI Agent Orchestrator. Deterministic functions are deliberately used for security-critical operations that require consistent and verifiable results, while AI-assisted reasoning is restricted to tasks where interpretation and contextual explanation are beneficial.

**Table 4.3 summarises the planned classes and modules, their type, and their primary responsibility.**

**Table 4.3 Summary of Planned Classes and Modules**

Component

Type

Primary Responsibility

Related Requirement

StreamlitDashboard

Module

Initiates assessment; retrieves and displays results

FR14, STR06

AIAgentOrchestrator

Class

Coordinates workflow and delegates tasks to agents

FR05, FR08, FR09, FR10, FR16

ScannerAgent

Class

Collects and evaluates Windows Server configuration

FR01, FR02, FR03, FR04

AnalysisAgent

Class

Processes findings; obtains risk score and LLM explanation

FR05, FR06, FR07

RemediationAgent

Class

Executes approved remediation and triggers verification

FR09, FR10, FR11

RiskEngine

Class

Performs deterministic risk-score calculation

FR06, FR07

LocalLLMClient

Class

Generates interpretive explanations from the local LLM

STR04, NFR07

CISControl

Data Class

Represents a single selected CIS control and expected value

Section 3.2.2, Table 3.2

DatabaseManager

Class

Stores and retrieves assessment, risk, remediation, verification, and historical data

FR12, FR13, STR05

*ConfigurationDrift/drift detection implemented via DatabaseManager

<a id="report-section-4-5"></a>

### 4.5 Database Design

This section presents the design of the local database that supports the framework’s data storage requirements. Consistent with FR12 and NFR04, the database provides persistent storage for assessment, risk, remediation, approval, verification, and configuration history information, and is accessed exclusively through the DatabaseManager class described in Section 4.4.1. The design is presented as an Entity-Relationship Diagram and an accompanying data dictionary, covering the schema and the fields of each entity, respectively.

<a id="report-section-4-5-1"></a>

#### 4.5.1 Entity-Relationship Diagram and Schema

*Source image 7 (`word/media/image18.jpg`): retained in the [original DOCX](<C:/Users/User/Downloads/RIS_KhooTengYi_Report.docx>); pixels are not embedded in this text transcription.*

**Figure 4.6 Entity-Relationship Diagram**

**Figure 4.6 presents the Entity-Relationship Diagram for the framework. The design consists of nine entities, organised into five functional groups that mirror the workflow described in Section 4.3: a reference group (CISControl, ControlRiskBaseline), an assessment group (Assessment, AssessmentResult), an analysis group (RiskScore), a remediation group (Remediation, Approval, Verification), and a history group (ConfigurationDrift).**

CISControl is a reference entity holding the predefined CIS benchmark information, control identifier, security area, and expected configuration value, against which the Scanner Agent evaluates a server, corresponding to the control catalogue in Table 3.2. Each control is assessed in many assessment results (1:M), since the same control is re-evaluated across every assessment run.

ControlRiskBaseline is a reference entity holding the fixed baseline scores for Security Impact (I), Privilege Impact (P), and Likelihood (L) for a control, derived using the method described in Section 4.6.2.3. It has a 1:1 relationship with CISControl, since these three factors are treated as intrinsic properties of the control itself rather than of a specific assessment (Section 4.6.2.3), and each control therefore has exactly one baseline record. Separating this data from CISControl rather than adding the baseline fields directly to it keeps the reference catalogue (identifier, expected value, benchmark reference) distinct from the risk-scoring rationale, and allows the rationale field to document the Benchmark evidence used for each score without expanding CISControl itself. During risk calculation, the Analysis Agent retrieves the relevant ControlRiskBaseline record for a control and combines its I, P, and L values with the Exposure (E) and Configuration State or Drift (D) values determined for that specific assessment (Section 4.6.2), before storing the complete set of five factor scores in RiskScore.

Assessment represents a single assessment execution initiated by the Administrator, while AssessmentResult stores the outcome for one control within that execution: the observed configuration, expected configuration, and compliance status, directly reflecting FR04. One Assessment contains many AssessmentResult records (1:M).

RiskScore has a relationship of 1:0..1 with AssessmentResult, holding the five risk factors and the resulting score and risk level for a non-compliant finding, per FR06 and FR07. A compliant result does not require a risk record, which is why the relationship is optional on the RiskScore side. Consistent with the risk-scoring formula in Section 4.6.2.4, risk_score is stored as an integer in the 20 to 100 range rather than a decimal.

Remediation has a 1:0..1 relationship with AssessmentResult, storing the selected remediation action drawn from the pre-approved PowerShell library (Section 4.6.3). Approval has a 1:0..1 relationship with Remediation, capturing the Administrator's decision (FR09, FR15) as its own record rather than a status flag on Remediation, so the decision, decision-maker, and timestamp are preserved independently of the remediation's execution state. Verification has a 1:0..M relationship with Remediation, storing the post-remediation check (FR11). This is one-to-many because the same approved Remediation record may be re-verified: if verification fails, the Orchestrator moves to Remediation Review, where the Administrator may approve re-running the same action or a corrective follow-up, and each re-check is stored as a new Verification record against the original Remediation, preserving the full verification history. Where the follow-up instead constitutes a distinct remediation action, a new Remediation record (with its own Approval and Verification) is created instead.

ConfigurationDrift records a comparison between two AssessmentResult records for the same control across different assessments (FR13). It is linked to AssessmentResult through two distinct relationships: a current result in relationship (1:0..1), since a given result can only ever be the current side of one drift comparison, and a previous result in relationship (1:0..M), since a result may later be referenced as the previous side of more than one comparison. Each ConfigurationDrift record therefore holds two foreign keys, current_result_id and previous_result_id, both referencing AssessmentResult, allowing configuration history to be reconstructed without altering any stored result. The existence of a ConfigurationDrift record itself represents that a change was detected between the two compared results, so no separate flag is stored to indicate this.

This design keeps the database structure traceable to the system requirements while maintaining a clear distinction between the workflow sequence of Remediation > Approval > Execution > Verification (Section 4.3.2) and the database relationships between the corresponding entities.

<a id="report-section-4-5-2"></a>

#### 4.5.2 Data Dictionary

**Table 4.4 CISControl**

Field name

Data type

Description

Example/value

control_id

VARCHAR (PK)

Unique identifier for the CIS control

“ CIS-1.2.2”

control_title

VARCHAR

Short name of the control

“Account lockout threshold”

security_area

VARCHAR

Security domain the control belongs to

“Account Policies”

expected_value

VARCHAR

Benchmark-defined compliant value

“10 invalid attempts”

benchmark_reference

VARCHAR

CIS benchmark section reference

“CIS Benchmark 1.2.2”

**Table 4.5 ControlRiskBaseline**

Field name

Data type

Description

Example/value

baseline_id

INT (PK)

Unique identifier for the baseline record

12

control_id

VARCHAR (FK, UNIQUE)

Control this baseline applies to

“ CIS-1.2.2”

security_impact_baseline

INT

Fixed Security Impact score for this control

4

privilege_impact_baseline

INT

Fixed Privilege Impact score for this control

3

likelihood_baseline

INT

Fixed Likelihood score for this control

3

rationale

TEXT

Benchmark evidence used to justify the scores (Section 4.6.2.3)

Governs account lockout threshold; Rationale ties to brute-force credential attacks (CIS, 2026)

**Table 4.6 Assessment**

Field name

Data type

Description

Example/value

assessment_id

INT (PK)

Unique identifier for the assessment run

1042

initiated_by

VARCHAR

Administrator who started the assessment

“admin01”

start_time

DATETIME

Time the assessment began

2026-08-12 09:15:00

end_time

DATETIME

Time the assessment was completed

2026-08-12 09:18:42

status

VARCHAR

Current state of the run

“Completed”

**Table 4.7 AssessmentResult**

Field name

Data type

Description

Example/value

result_id

INT (PK)

Unique identifier for the result record

5031

assessment_id

INT (FK)

Assessment this result belongs to

1042

control_id

VARCHAR (FK)

Control that was assessed

“ CIS-1.2.2”

observed_value

VARCHAR

Configuration value found on the server

“0 invalid attempts”

expected_value

VARCHAR

Expected compliant value at time of scan

“10 invalid attempts”

compliance_status

VARCHAR

Outcome of the comparison

“Non-Compliant”

assessed_at

DATETIME

Time this control was evaluated

2026-08-12 09:16:03

Constraint

UNIQUE (assessment_id, control_id)

Ensures each control has one result within an assessment run

-

**Table 4.8 RiskScore**

Field name

Data type

Description

Example/value

risk_id

INT (PK)

Unique identifier for the risk record

811

result_id

INT (FK, UNIQUE)

Non-compliant result this score belongs to

5031

security_impact

INT

Severity of impact if exploited

4

exposure

INT

How exposed the weakness is

3

privilege_impact

INT

Privilege level affected

3

likelihood

INT

Likelihood of exploitation

3

drift_score

INT

Configuration State or Drift score

1

risk_score

INT

Calculated composite score (20–100)

62

risk_level

VARCHAR

Categorised risk level

“High”

**Table 4.9 Remediation**

Field name

Data type

Description

Example/value

remediation_id

INT (PK)

Unique identifier for the remediation record

302

result_id

INT (FK, UNIQUE)

Finding this remediation addresses

5031

action_name

VARCHAR

Name of the selected remediation action

“Set account lockout threshold”

script_reference

VARCHAR

Identifier of the predefined PowerShell script

“REM-1.2.2”

status

VARCHAR

Current state of the action

“Awaiting Approval”

executed_at

DATETIME

Time the action was executed, if applicable

2026-08-12 09:25:11

**Table 4.10 Approval**

Field name

Data type

Description

Example/value

approval_id

INT (PK)

Unique identifier for the approval record

118

remediation_id

INT (FK, UNIQUE)

Remediation this decision applies to

302

administrator_id

VARCHAR

Administrator who made the decision

“admin01”

decision

VARCHAR

Approve or reject

“Approved”

decision_time

DATETIME

Time the decision was made

2026-08-12 09:20:47

comments

TEXT

Optional administrator remarks

“Approved, low-risk change”

**Table 4.11 Verification**

Field name

Data type

Description

Example/value

verification_id

INT (PK)

Unique identifier for the verification record

205

remediation_id

INT (FK)

Remediation this check applies to

302

verified_value

VARCHAR

Configuration value found after remediation

“10 invalid attempts”

verification_status

VARCHAR

Outcome of the check

“Passed”

verified_at

DATETIME

Time the verification was performed

2026-08-12 09:26:30

**Table 4.12 Configuration Drift**

Field name

Data type

Description

Example/value

drift_id

INT (PK)

Unique identifier for the drift record

44

current_result_id

INT (FK)

Result from the current assessment

5031

previous_result_id

INT (FK)

Result from the previous comparable assessment

4877

change_description

TEXT

Description of what changed

“Lockout threshold reverted to 0”

detected_at

DATETIME

Time the comparison was performed

2026-08-12 09:16:05

<a id="report-section-4-5-3"></a>

#### 4.5.3 Data Sources and Result Generation

**Table 4.13 Framework Data Sources and Result Generation**

| Information | Example | How It Is Obtained |
| --- | --- | --- |
| Observed Configuration | MinimumPasswordLength = 10 | The Scanner Agent runs the permitted PowerShell assessment function and stores the actual configuration value returned by Windows Server. |
| Expected Configuration | MinimumPasswordLength = 14 | Retrieved from the predefined CIS control data maintained by the system for the corresponding control. |
| Compliance Status | Non-Compliant | Determined by the deterministic assessment function by comparing the observed configuration with the predefined expected configuration. |
| Risk Information | Risk Score = 79, Risk Level = High | Generated using the predefined risk factors and deterministic calculation defined in Section 4.6.2. |
| Remediation Result | Execution Status = Executed | Recorded after the administrator approves the predefined remediation action and the Remediation Agent executes it. |
| Verification Result | Verification = Passed | Obtained by reassessing the affected configuration after remediation and comparing the resulting value with the expected configuration. |
| Assessment History | Assessment A001: 10 > Assessment A002: 14 | Stored as separate assessment records in the local database, allowing previous and current assessment results to be retrieved and compared. |
| Configuration Drift | Previous = 14, Current = 10 > <br>Drift Detected | Determined by comparing the current observed configuration with the corresponding value from a previous comparable assessment. |

<a id="report-section-4-6"></a>

### 4.6 Core Security Process Design

This section presents the detailed design of the four core security processes that implement the assessment, prioritisation, remediation, and monitoring functions established in Chapter 3. While Section 4.3 described the overall agent workflow and orchestration logic, and Section 4.4 described the module and class structure supporting that workflow, this section focuses on the internal logic of each individual process, the specific decision points, data transformations, and stored outcomes involved in evaluating a control, prioritising a finding, remediating a configuration, and detecting configuration drift.

Each process is presented as a flowchart illustrating its sequence of decisions and actions, together with a description of how the process interacts with the CISControl, ControlRiskBaseline, AssessmentResult, RiskScore, Remediation, Verification, and ConfigurationDrift entities defined in the Entity-Relationship Diagram (Figure 4.6). The four processes implement the functional requirements defined in Section 3.2.3 and operationalise the workflow presented in Section 3.3.

<a id="report-section-4-6-1"></a>

#### 4.6.1 CIS Compliance Assessment Process

*Source image 8 (`word/media/image10.jpg`): retained in the [original DOCX](<C:/Users/User/Downloads/RIS_KhooTengYi_Report.docx>); pixels are not embedded in this text transcription.*

**Figure 4.7 CIS Compliance Assessment Process**

The CIS Compliance Assessment Process illustrates how the Scanner Agent evaluates each selected control once an assessment is initiated by the Administrator. The Orchestrator delegates the scan task to the Scanner Agent, which selects the next control defined in Table 3.2 and invokes the corresponding Python assessment function to collect the observed configuration value through PowerShell. The observed value is compared against the predefined expected value; the control is classified as Compliant or Non-Compliant accordingly, and the result is recorded and stored in the database. This process repeats for each remaining control. Once all selected controls have been evaluated, the compliance results are returned to the Orchestrator, and any non-compliant findings are forwarded to the Analysis Agent for risk prioritisation (Section 4.6.2).

<a id="report-section-4-6-2"></a>

#### 4.6.2 Risk Prioritisation Process

*Source image 9 (`word/media/image5.jpg`): retained in the [original DOCX](<C:/Users/User/Downloads/RIS_KhooTengYi_Report.docx>); pixels are not embedded in this text transcription.*

**Figure 4.8 Risk Prioritisation Process**

Risk prioritisation is performed deterministically by the RiskEngine; the Local LLM provides supporting explanations but does not assign, calculate, or modify numerical risk values.The framework evaluates each non-compliant finding using five predefined risk factors: Security Impact (I), Exposure (E), Privilege Impact (P), Likelihood (L), and Configuration State or Drift (D).

The Risk Prioritisation Process illustrates how the Analysis Agent determines the relative significance of a non-compliant finding. For each finding, the fixed baseline scores for Security Impact (I), Privilege Impact (P), and Likelihood (L) are retrieved from the predefined ControlRiskBaseline dataset (Section 4.6.2.3), since these factors are treated as built-in properties of the control rather than of the specific assessment. The Analysis Agent sends the finding context to the Local LLM to obtain a human-readable interpretation and explanation of the security issue. This explanation is provided as supporting information and does not determine any numerical risk factor.

The Analysis Agent then determines the Exposure (E) score by applying the predefined Exposure criteria in Table 4.14b to the observed configuration and relevant security context of the affected control. The Configuration State or Drift (D) factor is determined according to the criteria in Table 4.14e. When a previous comparable assessment exists, the detected configuration change from the drift comparison described in Section 4.6.4 is also considered. The five factor scores are then combined using the weighted formula defined in Section 4.6.2.4 and the factor weights in Table 4.16 to calculate the final risk score R, which is classified into a risk level using the thresholds in Table 4.17. The resulting factor scores, risk score, and risk level are stored as a RiskScore record, and the prioritised finding is returned to the Orchestrator to proceed to remediation (Section 4.6.3).

<a id="report-section-4-6-2-1"></a>

##### 4.6.2.1 Risk Factor

The proposed risk-prioritisation method evaluates each non-compliant security control using five factors: Security Impact (I), Exposure (E), Privilege Impact (P), Likelihood (L), and Configuration State or Drift (D). Each factor represents a different characteristic of the security finding and is assigned a predefined score from 1 to 5. The factors are evaluated together to provide a contextual assessment of the relative risk associated with a non-compliant control.

Security Impact (I) represents the potential effect of the security weakness if it is exploited or remains unresolved. A higher score indicates that the affected control could have a greater effect on the confidentiality, integrity, availability, or overall security of the Windows Server.

Exposure (E) represents the degree to which the affected service, function, or configuration is exposed to potential attack. A higher score indicates greater exposure, such as security functionality that is accessible through network connections or remote access.

Privilege Impact (P) represents the level of privilege or access that could be affected if the weakness were misused. A higher score indicates that exploitation or misuse of the affected configuration could provide greater access to system resources or administrative functions.

Likelihood (L) represents the estimated likelihood that the weakness could be misused or exploited based on the intrinsic characteristics of the affected security control and supporting benchmark evidence. The factor provides additional context for prioritising findings that may require greater attention.

Configuration State or Drift (D) represents the degree to which the current configuration differs from the expected secure configuration or has changed from a previously assessed state. A greater deviation indicates a larger difference from the defined security baseline and may increase the priority of the finding.

The five factors are evaluated independently before being combined through the predefined weighting and calculation method. This allows the framework to consider different characteristics of a security finding rather than assigning the same priority to every non-compliant control.

<a id="report-section-4-6-2-2"></a>

##### 4.6.2.2 Risk Factor Scoring Rubric

Each risk factor is assigned a score from 1 to 5 using predefined criteria. The criteria are applied to the available configuration evidence and relevant security context to provide a consistent basis for assigning numerical values to non-compliant findings. The scoring process is deterministic, and the LLM does not independently assign or modify the numerical factor scores.

The general interpretation of the scoring scale is presented in Table 4.14.

**Table 4.14 General Risk Factor Scoring Scale**

| Score | General Interpretation |
| --- | --- |
| 1 | Very low contribution to risk |
| 2 | Low contribution to risk |
| 3 | Moderate contribution to risk |
| 4 | High contribution to risk |
| 5 | Very high contribution to risk |

The factor-specific criteria are defined as follows.

Security Impact (I)

The Security Impact score represents the potential consequence associated with the affected security control.

**Table 4.14a Security Impact**

| Score | Criteria |
| --- | --- |
| 1 | Failure has limited security consequences and affects a narrowly scoped security function. |
| 2 | Failure may cause a minor reduction in the security posture of the system. |
| 3 | Failure may affect an important security function or increase the possibility of unauthorised activity. |
| 4 | Failure may significantly affect system security or expose important system resources. |
| 5 | Failure may result in severe compromise of critical security functions, sensitive resources, or system protection. |

Exposure (E)

The Exposure score represents the degree to which the affected function or service is accessible to potential attackers.

**Table 4.14b Exposure**

| Score | Criteria |
| --- | --- |
| 1 | The affected function has minimal exposure and is not normally accessible through network connections. |
| 2 | The affected function has limited exposure within the local or controlled environment. |
| 3 | The affected function is accessible within the network or through controlled remote access. |
| 4 | The affected function has significant network or remote exposure. |
| 5 | The affected function is highly exposed and may be directly accessible through an untrusted or externally reachable network. |

Privilege Impact (P)

The Privilege Impact score represents the level of access that could potentially be affected if the security weakness is misused.

**Table 4.14c Privilege Impact**

| Score | Criteria |
| --- | --- |
| 1 | The finding has minimal implications for user privileges or system access. |
| 2 | The finding may affect access to limited user-level functions. |
| 3 | The finding may affect access to important user or system functions. |
| 4 | The finding may contribute to elevated or administrative access. |
| 5 | The finding may directly affect highly privileged or administrative access to the system. |

Likelihood (L)

The Likelihood score represents the estimated possibility that the identified weakness could be misused or exploited based on available security evidence.

**Table 4.14d Likelihood**

| Score | Criteria |
| --- | --- |
| 1 | There is limited evidence or opportunity for misuse or exploitation. |
| 2 | Misuse is possible but requires relatively specific conditions. |
| 3 | Misuse or exploitation is reasonably possible under common conditions. |
| 4 | There is strong evidence or a practical opportunity for misuse or exploitation. |
| 5 | There is strong evidence of active, common, or highly plausible exploitation or misuse. |

Configuration State or Drift (D)

The Configuration State or Drift score represents the assessment-history context of a non-compliant configuration, based on the availability and outcome of a previous comparable assessment.

**Table 4.14e Configuration State or Drift**

| Score | Criteria |
| --- | --- |
| 1 | No previous comparable assessment result is available |
| 3 | A previous comparable result exists and the observed configuration remains non-compliant without a detected change. |
| 5 | The previous result was compliant and the current result is non-compliant, indicating confirmed configuration drift. |

When no previous comparable assessment result exists, D is assigned a score of 1. When a previous comparable result exists and the observed configuration remains non-compliant without a detected change, D is assigned a score of 3. When the previous result was compliant and the current result is non-compliant, D is assigned a score of 5 to represent confirmed configuration drift.

<a id="report-section-4-6-2-3"></a>

##### 4.6.2.3 Baseline Risk Score Derivation

**Table 4.14 and the factor-specific rubrics in Section 4.6.2.2 explain how a score from 1 to 5 should be interpreted. They do not explain how the actual baseline value is decided for a given control's Security Impact (I), Privilege Impact (P), and Likelihood (L). Since these three factors are treated as intrinsic properties of a control rather than of a specific assessment (Section 4.6.2.3), the framework needs a repeatable, evidence-based method for assigning them.**

Primary source: the CIS Benchmark itself.

Each control entry in the CIS Microsoft Windows Server 2022 Benchmark (v5.1.0) already documents several attributes that can be used as scoring evidence (Center for Internet Security [CIS], 2026):

A Rationale and Impact description, explaining in CIS's own words why the setting matters and what the consequence of misconfiguration is.

A category grouping, showing which security area the control belongs to (e.g. Account Policies, User Rights Assignment, Security Options, Windows Defender Firewall, Advanced Audit Policy).

A Profile Level: Level 1 (general-purpose, broadly applicable to most environments) or Level 2 (specialised, intended for higher-security environments).

An Assessment Status, showing whether the setting can be checked automatically or requires manual review.

Each of the three factors is mapped to a specific one of these attributes:

**Table 4.15 Factor and Benchmark evidence used**

Factor

Benchmark evidence used (CIS, 2026)

Scoring logic

Security Impact (I)

Rationale / Impact text

Where the stated consequence involves authentication, credential exposure, or encryption = higher score. Where the consequence is mainly informational or cosmetic (e.g. logging visibility only) = lower score.

Privilege Impact (P)

Category, and any named user right or group

Where the control governs administrative access or the Local Security Authority = higher score. Where it governs standard, non-privileged user settings = lower score.

Likelihood (L)

Profile Level + Assessment Status

Level 1 and automatically-assessable controls = higher score, since they apply more broadly and are more commonly checked/misconfigured. Level 2 and manually-assessed controls = lower score, since they apply under more specific conditions.

This keeps the logic consistent with what Section 4.6.2.3 already states about Likelihood, that it is inferred from the nature of the control, not from real-time threat intelligence.

Who assigns the scores, and when.

Consistent with the deterministic design principle in Section 4.6.2.3, this method is applied once, by the researcher, during control catalogue design, not by the Local LLM, and not at assessment runtime. Exposure (E) is determined separately at assessment time by applying the predefined Exposure scoring criteria in Table 4.14b to the observed configuration and relevant security context of the affected control. The Local LLM does not determine or influence the Exposure score.

<a id="report-section-4-6-2-4"></a>

##### 4.6.2.4 Risk Factor Weighting and Calculation

The five risk factors are assigned different weights according to their relative importance in determining the overall significance of a non-compliant Windows Server security control. Because the framework evaluates configuration compliance rather than software vulnerabilities, the weighting scheme prioritises factors that best reflect the potential consequence and accessibility of a misconfiguration in a Windows Server environment. (FIRST, 2023; Jacobs et al., 2023)

Security Impact (I) is given the highest weight (30%). The potential consequence of a security weakness is the primary consideration when determining its significance. For example, a weak password policy or an unrestricted Remote Desktop configuration can directly enable unauthorised access or privilege escalation, producing high-impact outcomes if exploited.

Exposure (E) receives the second-highest weight (25%). Greater accessibility to potential attackers increases the opportunity for misuse. Controls related to firewall rules, Remote Desktop Services, or network-facing authentication settings are more likely to be reachable by external or internal attackers than purely local account settings, and therefore warrant higher prioritisation when non-compliant.

Privilege Impact (P) is assigned the third-highest weight (20%). Weaknesses that affect higher levels of system access, such as settings related to administrator accounts or authentication controls, can amplify the potential consequences of a successful attack. This factor therefore contributes meaningfully to the overall score, though it is secondary to the direct impact and exposure of the control itself.

Likelihood (L) is assigned a lower weight (15%). It provides additional context regarding the possibility of misuse or exploitation based on the available security environment. In a configuration-focused assessment, likelihood is inferred from the nature of the control and supporting system context rather than from real-time threat intelligence or exploit prediction data. As a result, it is treated as a supporting factor rather than a dominant one.

Configuration State or Drift (D) receives the lowest weight (10%). It supplies useful historical context by indicating whether a control has recently changed from a compliant to a non-compliant state. While drift is important for monitoring and long-term maintenance, it does not by itself determine the inherent severity of the current misconfiguration. Consequently, it is given the smallest contribution to the final score.

The weighting used by the proposed framework is summarised in Table 4.16.

**Table 4.16 Risk Factor Weights**

| Risk Factor | Symbol | Weight |
| --- | --- | --- |
| Security Impact | I | 30% |
| Exposure | E | 25% |
| Privilege Impact | P | 20% |
| Likelihood | L | 15% |
| Configuration State or Drift | D | 10% |
| Total |  | 100% |

This weighting scheme is a project-defined prioritisation method developed specifically for selected CIS-aligned Windows Server configuration findings. The selected weights are defined by the proposed framework and are not directly taken from the CIS Benchmark or CVSS. It places greater emphasis on the potential impact and exposure of a security finding while still incorporating privilege implications, likelihood of misuse, and configuration state. The weights are applied consistently to all non-compliant controls evaluated by the framework, ensuring that prioritisation remains repeatable and comparable across assessments. (FIRST, 2023; Jacobs et al., 2023).

The present method adapts this general principle to the specific domain of Windows Server configuration compliance rather than software vulnerability scoring. The five factors and their relative weights were therefore defined according to the characteristics of CIS Benchmark controls, with higher importance given to the potential security consequence and accessibility of a misconfiguration.

Since each risk factor is assigned a score from 1 to 5, the final risk score is calculated as:

R = 20 * (0.30I + 0.25E + 0.20P + 0.15L + 0.10D)

where:

I   = Security Impact score

E  = Exposure score

P  = Privilege Impact score

L  = Likelihood score

D  = Configuration State or Drift score

R  = final risk score ranging from 20 to 100

The multiplier of 20 converts the weighted average (which lies between 1 and 5) into a 20 to 100 scale. Equivalently, the same result can be obtained by expanding the expression:

R = (I * 6) + (E * 5) + (P * 4) + (L * 3) + (D * 2)

because 0.30 * 20 = 6, 0.25 * 20 = 5, and so on. A score of 20 represents the lowest possible combination of factor scores (all factors = 1). A score of 100 represents the highest possible combination (all factors = 5).

The final risk score is calculated deterministically after the five factor scores have been assigned. The local LLM is used to interpret supporting information and generate explanations, but it does not perform the numerical calculation or modify the resulting score. This design ensures that prioritisation remains consistent, transparent, and independent of any variability in language-model output. The calculated score is subsequently used by the framework to classify and prioritise non-compliant findings according to the risk classification defined in the following section.

<a id="report-section-4-6-2-5"></a>

##### 4.6.2.5 Risk Classification and Prioritization

The final risk score produced by the weighted calculation ranges from 20 to 100. To provide a clearer interpretation of the calculated score, the framework classifies non-compliant findings into four risk levels: Low, Moderate, High, and Critical. The classification provides administrators with a consistent indication of the relative priority of each finding.

**Table 4.17 Risk Classification**

| Risk Score | Risk Level | Priority | Interpretation |
| --- | --- | --- | --- |
| 20-39 | Low | 4 | The finding represents a relatively low security concern and may be addressed after higher-priority findings. |
| 40-59 | Moderate | 3 | The finding represents a noticeable security concern and should be considered for remediation. |
| 60-79 | High | 2 | The finding represents a significant security concern and should receive relatively high remediation priority. |
| 80-100 | Critical | 1 | The finding represents a very significant security concern and should receive the highest remediation priority. |

*Priority 1 = highest priority and Priority 4 = lowest priority

The risk level is determined directly from the calculated risk score using the predefined score ranges. Findings with higher risk scores receive higher remediation priority. When multiple findings have the same risk level, their numerical risk scores can be used to establish their relative order, with the higher score receiving the higher priority.

The classification thresholds are defined as part of the proposed risk-prioritisation method and are applied consistently across the selected CIS controls. These thresholds are project-defined prioritisation categories and are not intended as a replacement for CVSS.

The resulting risk level and priority are stored together with the corresponding assessment result. These values can then be used by the Analysis Agent and dashboard to present the most significant non-compliant findings to the administrator.

<a id="report-section-4-6-3"></a>

#### 4.6.3 Remediation and Verification Process

*Source image 10 (`word/media/image20.jpg`): retained in the [original DOCX](<C:/Users/User/Downloads/RIS_KhooTengYi_Report.docx>); pixels are not embedded in this text transcription.*

**Figure 4.9 Remediation and Verification Process**

The Remediation and Verification Process illustrates how a prioritised finding is handled after it is returned to the AI Agent Orchestrator. The Orchestrator identifies an applicable remediation action from the predefined PowerShell library and presents the finding, its risk information, and the proposed action to the Administrator for review. If the Administrator rejects the action, the rejection is recorded without any configuration change, and the assessment is marked complete. If approved, the Orchestrator delegates the remediation task to the Remediation Agent, which executes the approved PowerShell action and reassesses the affected control. Where verification passes, the control is recorded as Compliant, and the verification result is stored. Where verification fails, the workflow moves to Remediation Review, where a further remediation action may be determined and must again be presented to the Administrator for approval before execution. This maintains the human-in-the-loop control established in NFR01 and FR09.

Post-remediation verification uses the same predefined assessment function and expected secure configuration used during the original CIS compliance assessment, ensuring that remediation success is determined using the same compliance criteria.

A remediation action is not considered successful solely because the PowerShell action executes without error. The affected configuration must subsequently satisfy the predefined expected CIS configuration during post-remediation verification before the remediation is recorded as successful.

<a id="report-section-4-6-4"></a>

#### 4.6.4 Configuration Drift Detection Process

*Source image 11 (`word/media/image7.jpg`): retained in the [original DOCX](<C:/Users/User/Downloads/RIS_KhooTengYi_Report.docx>); pixels are not embedded in this text transcription.*

**Figure 4.10 Configuration Drift Detection Process**

The Configuration Drift Detection Process illustrates how the framework identifies changes between a current and a previous comparable assessment of the same control. When a new AssessmentResult is stored, the framework checks whether a previous comparable assessment exists for the same control_id. If none exists, no comparison is possible, and no drift record is created. If a previous result exists, the current and previous observed values are compared; where the values differ, a ConfigurationDrift record is created, storing the current and previous result identifiers, a description of the change, and a timestamp, and this record is stored in the database. The detected drift may subsequently be used as the Configuration State or Drift (D) factor in a later risk calculation (Section 4.6.2), and is also made available on the dashboard for administrator review.

<a id="report-section-4-7"></a>

### 4.7 User Interface Design

The following figures present Streamlit dashboard mock-ups populated with representative sample data. They illustrate the proposed interface; no live agent or database connection is implied. The interface is designed as a Streamlit-based dashboard and is intended to present the results generated by the framework’s core processes, including compliance assessment, risk prioritisation, remediation approval, verification, and configuration drift detection. The design focuses on presenting security information in a form that supports administrator review and decision-making without exposing unnecessary implementation details.

The dashboard is organised into several functional views, with each view corresponding to a specific stage or output of the security workflow. The following subsections describe the purpose and information presented by each interface.

<a id="report-section-4-7-1"></a>

#### 4.7.1 Dashboard / Overview Interface

*Source image 12 (`word/media/image13.png`): retained in the [original DOCX](<C:/Users/User/Downloads/RIS_KhooTengYi_Report.docx>); pixels are not embedded in this text transcription.*

**Figure 4.11(a): Dashboard / Overview Interface and Current Device Situation**

The Dashboard / Overview interface provides an executive summary of the Windows Server 2022 hardening assessment and serves as the starting point for the proposed framework. It displays the assessment identifier, scoped controls, sample compliance rate, number of non-compliant controls, and the highest calculated risk score, allowing the administrator to quickly understand the overall security posture before reviewing individual findings. The Current Device Situation section translates the most significant simulated weakness into plain language by explaining that Network Level Authentication is not required for Remote Desktop connections and why this increases exposure. The Agentic Workflow Replay section demonstrates how the AI Agent Orchestrator coordinates the Scanner Agent and Analysis Agent through the assessment process, while the Agent Activity area records the current workflow state. This interface uses representative sample data only and does not perform a live scan or modify the target server.

*Source image 13 (`word/media/image11.png`): retained in the [original DOCX](<C:/Users/User/Downloads/RIS_KhooTengYi_Report.docx>); pixels are not embedded in this text transcription.*

**Figure 4.11(b): Agentic Workflow Readiness, Assessment Summary, and Risk Distribution**

The lower section of the Dashboard / Overview interface presents the operational status of the agentic workflow and the supporting assessment evidence. The Agentic Workflow Replay function allows the administrator to initiate a representative assessment sequence, while the Agent Activity table records the actions and current state of the AI Agent Orchestrator. This makes the workflow transparent by showing that the framework is ready to begin scanning rather than performing hidden actions. The Assessment Information table provides the assessment identifier, initiating administrator, execution times, and completion status, supporting accountability and audit review. In addition, the Risk Distribution summary categorises the non-compliant findings by severity, and the Assessment Snapshot lists each sampled CIS control with its compliance outcome. Together, these components help the administrator understand the assessment status, prioritise significant findings, and proceed to detailed risk and remediation review.

*Source image 14 (`word/media/image15.png`): retained in the [original DOCX](<C:/Users/User/Downloads/RIS_KhooTengYi_Report.docx>); pixels are not embedded in this text transcription.*

**Figure 4.11(c): Agentic Assessment Execution and Awaiting Approval State**

The Agentic Workflow Replay section demonstrates how the proposed framework progresses through an assessment cycle before requesting an administrator decision. It shows the Scanner Agent reviewing the selected controls, followed by the Analysis Agent performing deterministic risk prioritisation. The Agent Activity log records each workflow event, including the responsible component, activity, timestamp, and current state, providing visibility into the actions coordinated by the AI Agent Orchestrator. After scanning and analysis are completed, the workflow transitions to the Awaiting Approval state. At this point, no remediation action is performed automatically; the administrator must review the findings and explicitly approve or reject the proposed action. This interface demonstrates the framework’s agent coordination and human-in-the-loop control mechanism.

<a id="report-section-4-7-2"></a>

#### 4.7.2 Assessment Results Interface

*Source image 15 (`word/media/image2.png`): retained in the [original DOCX](<C:/Users/User/Downloads/RIS_KhooTengYi_Report.docx>); pixels are not embedded in this text transcription.*

**Figure 4.12 Assessment Results Interface**

The Assessment Results interface provides a detailed view of the configuration evidence collected during an assessment. It enables the administrator to review each assessed control by comparing the observed configuration value with the expected security requirement and viewing the resulting compliance status. The filtering function allows the administrator to focus on all results, compliant controls, or non-compliant controls, while the summary indicator provides a quick overview of the assessment outcome. This interface supports transparent compliance assessment by presenting the evidence used to determine each result and directing the administrator to the Risk Findings / Risk Details interface for further review of non-compliant findings.

<a id="report-section-4-7-3"></a>

#### 4.7.3 Risk Findings / Risk Details Interface

*Source image 16 (`word/media/image12.png`): retained in the [original DOCX](<C:/Users/User/Downloads/RIS_KhooTengYi_Report.docx>); pixels are not embedded in this text transcription.*

**Figure 4.13(a): Risk Findings and Deterministic Risk-Scoring Details Interface**

The Risk Findings / Risk Details interface enables the administrator to prioritise non-compliant findings according to their calculated security risk. The upper table presents each finding with its risk score and severity level, allowing the administrator to identify which issues require the most urgent attention. A finding can be selected to display its detailed assessment, including the deterministic risk formula and the contributing Impact, Exposure, Privilege Impact, Likelihood, and Configuration Drift factors. The supporting explanation translates the technical security condition into understandable context for the administrator. This interface improves transparency by showing how risk priorities are calculated and supports informed remediation decisions without allowing the AI component to independently make security-critical changes.

*Source image 17 (`word/media/image9.png`): retained in the [original DOCX](<C:/Users/User/Downloads/RIS_KhooTengYi_Report.docx>); pixels are not embedded in this text transcription.*

**Figure 4.13(b): Device Security Context and Decision Support**

The Device Security Context and Decision Support section translates the selected technical finding into information that supports administrator decision-making. It explains that Network Level Authentication is not required for Remote Desktop connections and clarifies that this may expose the Remote Desktop logon prompt to unauthenticated network connections. Rather than applying a configuration change automatically, the interface recommends that the administrator confirm that authorised users have supported Remote Desktop clients before approving the remediation. It also presents the expected consequences of both possible decisions: approval requires earlier authentication and may require unsupported clients to be updated, while rejection or delay leaves the Critical Remote Desktop exposure unresolved. This supports the human-in-the-loop principle by providing clear security and operational context before the administrator makes a remediation decision.

<a id="report-section-4-7-4"></a>

#### 4.7.4 Remediation Review Interface

*Source image 18 (`word/media/image3.png`): retained in the [original DOCX](<C:/Users/User/Downloads/RIS_KhooTengYi_Report.docx>); pixels are not embedded in this text transcription.*

**Figure 4.14: Remediation Review Interface**

The Remediation Review interface provides the mandatory human-in-the-loop checkpoint before a proposed remediation action can proceed. It presents the selected finding, risk information, proposed remediation action, script reference, and decision-impact details so that the administrator can assess the security and operational implications of the proposed change. The review safeguard ensures that a remediation decision is available only after the assessment workflow has generated the relevant evidence. The administrator may enter an optional review comment and then explicitly select Approve or Reject. If the action is approved, the workflow proceeds automatically to the Verification / Remediation Result interface, where the execution and verification outcome are displayed. This ensures that configuration-changing actions remain under administrator control throughout the proposed workflow.

<a id="report-section-4-7-5"></a>

#### 4.7.5 Verification / Remediation Result Interface

*Source image 19 (`word/media/image17.png`): retained in the [original DOCX](<C:/Users/User/Downloads/RIS_KhooTengYi_Report.docx>); pixels are not embedded in this text transcription.*

**Figure 4.15 Verification / Remediation Result Interface**

The Verification / Remediation Result interface displays the final stage of the proposed remediation workflow. It records the executed remediation action, associated script reference, execution status, and execution time, allowing the administrator to review the outcome after approving a remediation request. The reassessment section compares the expected configuration value with the verified value and indicates whether the remediation has passed verification. This provides evidence that the intended security setting was achieved following the approved action. The Agent Activity area presents the workflow audit trail and confirms that the AI Agent Orchestrator has reached the Verification Passed state. This interface demonstrates the verification and accountability functions of the proposed framework using representative sample data only.

<a id="report-section-4-7-6"></a>

#### 4.7.6 Configuration Drift / Assessment History Interface

*Source image 20 (`word/media/image8.png`): retained in the [original DOCX](<C:/Users/User/Downloads/RIS_KhooTengYi_Report.docx>); pixels are not embedded in this text transcription.*

**Figure 4.16: Configuration Drift / Assessment History Interface**

The Configuration Drift / Assessment History interface enables the administrator to identify changes between the current assessment and a previous comparable assessment. The Detected Configuration Drift table presents the control identifier, previous value, current value, change description, and detection time, allowing the administrator to see when a security configuration has changed from its earlier recorded state. This information supports ongoing monitoring by highlighting configurations that may have been altered outside the remediation workflow and may therefore require further review. The Assessment History table provides a record of completed assessment runs, including the assessment identifier, initiating administrator, start time, and status. Together, these sections provide an audit trail of configuration changes and assessment activity, supporting the framework’s configuration-drift detection and security monitoring functions through representative sample data.

<a id="report-section-4-8"></a>

### 4.8 Chapter Summary

This chapter presented the system design of the proposed Agentic AI Framework for Windows Systems Hardening and CIS Compliance Assessment. The overall architecture, use case design, agent workflow, module and class structure, and database design were defined to establish the structure and interactions of the proposed framework. The design also specified the responsibilities of the AI Agent Orchestrator, Scanner Agent, Analysis Agent, and Remediation Agent, while maintaining the separation between deterministic security functions and the supporting Local LLM.

The core security processes were further designed to cover CIS compliance assessment, risk prioritisation, remediation and verification, and configuration drift detection. The user interface design was also presented through the dashboard views for assessment results, risk findings, remediation review, verification results, and configuration history. Together, these designs provide the structural and process foundation for the proposed framework and serve as the basis for the prototype development and system integration activities described in the subsequent chapter.

<a id="report-references"></a>

## References

Agyei, K. G., Monjoma, M. B., Samushonga, C. A., Chisora, H. H., Nemure, T., Gwangwava, S., & Mupa, M. N. (2026). Explainable risk-based vulnerability prioritization in hybrid cloud: Integrating CVSS, EPSS, and CISA KEV with asset criticality signals. World Journal of Advanced Research and Reviews, 30(1), 2044–2052. https://doi.org/10.30574/wjarr.2026.30.1.1006

Center for Internet Security. (2024). CIS Controls v8.1. https://www.cisecurity.org/controls

Center for Internet Security. (2026). CIS Microsoft Windows Server 2022 Benchmark (Version 5.1.0). https://www.cisecurity.org/benchmark/microsoft_windows_server

FIRST. (2023). Common Vulnerability Scoring System version 4.0: Specification document. https://www.first.org/cvss/v4.0/specification-document

Greenbone. (n.d.). Greenbone Community Edition documentation.

https://greenbone.github.io/docs/latest/

Guo, T., Chen, X., Wang, Y., Chang, R., Pei, S., Chawla, N. V., Wiest, O., & Zhang, X. (2024). Large language model based multi-agents: A survey of progress and challenges [Preprint]. arXiv. https://doi.org/10.48550/arXiv.2402.01680

Hasanov, I., Virtanen, S., Hakkala, A., & Isoaho, J. (2024). Application of large language models in cybersecurity: A systematic literature review. IEEE Access, 12, 176751–176778. https://doi.org/10.1109/ACCESS.2024.3505983

Jacobs, J., Romanosky, S., Suciu, O., Edwards, B., & Sarabi, A. (2023). Enhancing vulnerability prioritization: Data-driven exploit predictions with community-driven insights. In 2023 IEEE European Symposium on Security and Privacy Workshops (EuroS&PW) (pp. 194–206). IEEE. https://doi.org/10.1109/EuroSPW59978.2023.00027

Malatji, M. (2025). Augmented intelligence framework for human–artificial intelligence teaming in cybersecurity. Human-Centric Intelligent Systems, 5, 151–180. https://doi.org/10.1007/s44230-025-00103-8

Microsoft. (2026). Microsoft Security Compliance Toolkit 1.0 [Computer software]. https://www.microsoft.com/en-us/download/details.aspx?id=55319

Ollama. (n.d.). Introduction.

https://docs.ollama.com/api/introduction

OpenSCAP. (n.d.). OpenSCAP portal.

https://www.open-scap.org/

OWASP Foundation. (n.d.). AI agent security cheat sheet. https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html

OWASP Foundation. (2025). OWASP Top 10 for large language model applications 2025. https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/

Pascoe, C., Quinn, S., & Scarfone, K. (2024). The NIST Cybersecurity Framework (CSF) 2.0 (NIST CSWP 29). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.CSWP.29

Qwen Team. (n.d.). Qwen3 [Computer software]. GitHub.

 https://github.com/QwenLM/Qwen3

Schick, T., Dwivedi-Yu, J., Dessì, R., Raileanu, R., Lomeli, M., Hambro, E., Zettlemoyer, L., Cancedda, N., & Scialom, T. (2023). Toolformer: Language models can teach themselves to use tools. Advances in Neural Information Processing Systems, 36. https://proceedings.neurips.cc/paper_files/paper/2023/hash/d842425e4bf79ba039352da0f658a906-Abstract-Conference.html

Shahriar, A., Rahman, M. N., Ahmed, S., Sadeque, F., & Parvez, M. R. (2025). A survey on agentic security: Applications, threats, and defenses [Preprint]. arXiv. https://doi.org/10.48550/arXiv.2510.06445

Tabassi, E. (2023). Artificial intelligence risk management framework (AI RMF 1.0) (NIST AI 100-1). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.AI.100-1

Tenable. (n.d.). Tenable documentation.

https://docs.tenable.com/

Thiyagarajan, G., Bist, V., & Nayak, P. (2024). AI-driven configuration drift detection in cloud environments. International Journal of Communication Networks and Information Security, 16(5), 721–743. https://doi.org/10.2139/ssrn.5138379

Wu, Q., Bansal, G., Zhang, J., Wu, Y., Li, B., Zhu, E., Jiang, L., Zhang, X., Zhang, S., Liu, J., Awadallah, A. H., White, R. W., Burger, D., & Wang, C. (2023). AutoGen: Enabling next-gen LLM applications via multi-agent conversation [Preprint]. arXiv. https://doi.org/10.48550/arXiv.2308.08155

Yao, S., Zhao, J., Yu, D., Du, N., Shafran, I., Narasimhan, K., & Cao, Y. (2023). ReAct: Synergizing reasoning and acting in language models. In International Conference on Learning Representations. https://openreview.net/forum?id=WE_vluYUL-X

## Transcription audit

Extracted 1540 nonempty paragraphs (including table cells), 19 tables, 75 styled headings and 20 embedded-image occurrences. This is a content extraction check, not a rendered Word layout review.
