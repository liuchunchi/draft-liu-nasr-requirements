---
title: NASR Use Case and Requirements
abbrev: nasr-req
category: info

docname: draft-liu-nasr-requirements-03
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
# area: AREA
# workgroup: WG Working Group
keyword:
 - Network Attestation
 - Routing Security
venue:
#  group: WG
#  type: Working Group
#  mail: WG@example.com
#  arch: https://example.com/WG
  github: "liuchunchi/draft-liu-nasr-requirements"
  latest: "https://liuchunchi.github.io/draft-liu-nasr-requirements/draft-liu-nasr-requirements.html"

author:
 -
  ins: C. Liu
  name: Chunchi Liu
  organization: Huawei
  email: liuchunchi@huawei.com
 -
  ins: L. Iannone
  name: Luigi Iannone
  organization: Huawei
  email: luigi.iannone@huawei.com
 -
  ins: D. Lopez
  name: Diego Lopez
  organization: Telefonica
  email: "diego.r.lopez@telefonica.com"
 -
  ins: A. Pastor
  name: Antonio Pastor
  organization: Telefonica
  email: "antonio.pastorperales@telefonica.com"
 -
  ins: M. Chen
  name: Meiling Chen
  organization: China Mobile
  email: "chenmeiling@chinamobile.com"
 -
  ins: L. Su
  name: Li Su
  organization: China Mobile
  email: "suli@chinamobile.com"

normative:
  RFC2119:
  RFC8174:
  RFC7011:
  RFC8704:
  RFC792:

informative:
  RFC4593:
  RFC2828:
  RFC5635:
  I-D.ietf-sfc-proof-of-transit-08: CISCOPOT
  I-D.liu-path-validation-problem-statement: PV
  I-D.chen-secure-routing-use-cases-00: SECROUT
  I-D.voit-rats-trustworthy-path-routing: TPR
  I-D.ietf-rats-eat: RATSEAT
  I-D.ietf-rats-ar4si: RATSRES

  Yaar03: DOI.10.1109/SECPRI.2003.1199330

--- abstract

This document describes the use cases and requirements that guide the specification of a Network Attestation for Secure Routing framework (NASR).

--- middle

# Introduction {#intro}

This document outlines the use cases and requirements that guide the specification of a Network Attestation for Secure Routing framework (NASR).

## Note for NASR participants

This document collates and synthesizes discussion outcomes of NASR mailing list and side meetings.

It is created to help
  1. Foster consensus among list members.
  2. Orient non-list members to NASR goals and current progress

This document may become a WG-draft but will stay as an informational draft.

# Terminology {#term}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 {{RFC2119}}, {{RFC8174}} when, and only when, they appear in all capitals, as shown here.

# Backgrounds {#back}

Clients with high security and privacy requirements are not anymore satisfied with traffic signing and encryption mechanisms only; they now request information of the trustworthiness or security properties of the network paths over which the traffic is carried, preferably to choose the desired properties. 

# Definitions {#def}

We summarize the terms discussed in the list.

* NASR: Network Attestation For Secure Routing, a technical framework to be proposed that mainly does the following:
  1. Allow clients to choose desired security attributes of his received network service
  2. Achieve dependable forwarding by routing on top of only devices that satisfies his trust requirements
  3. Provide proof to the clients that certain packets or flows traversed a network path that has certain trust or security properties.

* Routing Security: Practices and protocols designed to protect the integrity, confidentiality, and availability of network routing information and processes. {{RFC4593}}, {{RFC2828}}

* Path Validation: The process of collecting the actual packet transit history and compare it against a baseline, in order to decide whether or not the actual forwarding situation satisfies the relying party. 

* Secure Routing: {{-SECROUT}}

* Proof-of-Transit: A verifiable cryptographic tag proving data of specific granularity was processed by a network device. {{-CISCOPOT}}

* Trustworthy Path Routing: Path computation and routing according to the trustworthiness of a network device, in order to avoid less trustworthy, unsecure or risky devices. {{-TPR}}

* Forwarding Baseline: A deterministic reference value that can be used in the path validation process.

...

## Trust Models

NASR is expected to operate in limited domains, in opposition of public Internets. 

Case 1: NASR operates inside of one single administrative limited domain as defined in {{RFC8799}}. In this case, within a confined network boundary, the operator maintains unified administrative control over device configurations through authenticated interfaces. All devices providing NASR services are equipped with basic RATS (Remote Attestation) capabilities.

Case 2: NASR also operates between two limited domains. In this case, in addition to the assumptions mentioned above, the two limited domain operators establish mutual trust through other technical or non-technical channels, aiming to collaboratively deliver consistent NASR functionalities. For instance, end-to-end connectivity services can be delivered either through collaboration between two sub-operating units within a single telecommunications group, or through contractual partnerships between separate telecom operators.

# Use Cases {#usecases}


## Use Case 1: Network Path Validation

Explicit routing protocols permit explicit control over the traffic path, in order to meet certain performance, security or compliance requirements. For example, operators can use SRv6 to orchestrate a Service Function Chaining (SFC) path and provide packaged security services or compliance services. For either of them, validating the actual packet trace in the forwarding plane as an auditing measure is needed for clients and/or authorities. NASR can help operator to attest to an orchestrated path and provide verifiable forwarding proofs to help clients/authorities audit the forwarding.

SFC is used as an example, therefore network elements are not limited to Service Functions, and paths are not limited to a SFC path. Other devices or network functions may incorporate features (built-in security capabilities, roots of trust and attestation mechanisms, etc.) needs to be validated. 

Another example is SRv6 strict mode vs loose mode. Compared to the former, SRv6 loose mode does not specify a fixed forwarding baseline. In which case, we may need to use dial-test-like methods to specify a legitimate forwarding baseline, and verify the actual packet trace against this forwarding baseline. If changes must be made, e.g. path re-calculation due to partial failures, the update of baseline is permitted but must be known to the relying party. 


## Use Case 2: Verifying Path Properties

In use case 1, the orchestrated path is explicit and specific down to each network element. Sometimes, clients do not need to know every detail of the network path. Rather, clients will request the verification of a certain property within the path, such as trustworthiness, security level, geolocation, vendor characteristics, transit provider, etc. from the operator. Using NASR, the operator can orchestrate this path by selecting network elements with the requested properties. In this case, the forwarding baseline does not contain specific hop-by-hop paths, but the set of security properties only. 

## Use Case 3: Sensitive Data Routing

Clients from specific industries such as finance or governments have very low tolerance to data leakage. These clients require assurance that their data only travels on top of their selected leased line and have (preferably real-time) verifiable evidence or proof. Some compliance requirements also prohibit customer data escape a specific geolocation without authorization. To avoid data leakage and compliance risks, some clients are willing to pay a premium for high data routing security guarantees. NASR can prevent and detect accidental violations and make corrections promptly, therefore supporting SLAs incorporating these guarantees.

Compared to the first and second use case, this use case might requires some preventive measures before a wrongful forwarding happens at the first place.

## Use Case 4: Sensitive data transmission due to remote AI training

This use case is similar to Use Case 3 but is more specific. As AI trend rise, operators are investing in "AI training centers" for lease. Due to scalability and cost reduction considerations, training centers tend to be built separately from data centers. In manufacturing industry or other data-heavy industries, DCs or private storage is often built next to the campus. But in order to support training and utilize operator-running training centers, wide-area data transmission between DC and TC is needed. Enterprise clients, when faced with privacy-sensitive data leaving their DCs and go through wide-area transmission, are highly unhappy. Yet, it is also impractical for operators to build dedicated training centers next to the client DC. Without NASR guaranteeing dependable forwarding and non-leakage, the market sales of operator's training center business is hindered. This is more of a business use case, but technically same with use case 1. 

## Use Case 5: Ingress Filtering

Ingress Filtering techniques help prevent source IP address spoofing and denial-of-service (DoS) attacks {{RFC8704}}{{RFC5635}}. Approches like uRPF works by validating the source IP address of a received packet by performing a reverse path lookup in FIB table, all the way to the source. If the path does not exist, the packet is dropped. NASR can be used to regularly validate the path stored in the FIB table, and tell if it continues to exist. Furthermore, when uRPF is not available and source address cannot be trusted, NASR can offer a way to filter malicious traffic based on the path used to carry out such an attack {{Yaar03}}. The other usage is to check if a packet carries a valid trail of transit proofs. If it does then the packet is verified. 


# Requirements {#requirements}

Based on the main use-cases described in the previous section the following requirements are identified.

## Requirement 1: Attributes of a network element, interfaces {#reqattributes}

According to goal 1 of NASR definition, NASR team will define security/trustworthiness attributes of network elements, for clients to request from operators. Attributes should be objective claims, including but not limited to existing remotely-attested claims, element type (physical or virtual network element), security capability it enables, cryptographic algorithms, key strength, deployed geolocation, etc. These attributes constructs a forwarding baseline needed for post-flight path validation. 

Such attributes/claims/attestation results can reuse existing specifications, for example {{-RATSEAT}}, {{-RATSRES}} in RATS WG. Some existing claims that we can reuse:

  - hwmodel (Hardware Model)
  - hwversion (Hardware Version)
  - swname (Software Name )
  - swversion (Software Version)
  - location (location)

Some new claim extensions can be made:

    elemtype
    index
    secfunctions
    vendor
    ...

(subject to discussion, add, change)

NASR could work closely with RATS on the standardization of above attributes and means of proving them.

Additionally, service request interface between clients and operators should also be defined. 

## Requirement 2: Forwarding Baseline

After a path attribute request is sent from the client to the operator, the operator will have to choose qualifying devices and calculate a L3 path. This L3 path (or routing baseline) must be translated to a deterministic forwarding baseline using dial-tests or device-controller communications. The actual packet trace should be verified against the forwarding baseline. The forwarding baseline should keep unchanged during the process, unless necessary events happen and the re-calculation result notifies the relying party. 

## Requirement 3: Path Attestation Procedures

The path attestation procedure will be the core protocol of NASR. It contains steps to create the forwarding baseline and verifying actual packet trace against it. Details are being designed in the NASR architecture document. 

## Requirement 4: Proof-of-Transit (POT) Mechanisms {#reqpot}


All use cases requested public verifiability of packet transit history. Proof-of-Transit (POT) is a proof that a packet transited certain network elements, and it can include a verification of the order in which those elements where transited (Ordered POT, OPoT) or not. A secure POT mechanism should verifiably reflect the identity of the transited network elements and their relevant attributes, if applicable:

 - For basic POT, there is no further attribute than the identity of the transited element and, optionally, its relative position/order within the path. This is the goal of the POT mechanism defined in {{-CISCOPOT}}.

 - For extended POT, different attributes can be considered from a list of relevant ones: trustworthiness measure, available security capabilities, geolocation, vendor, etc. This needs the definition of the relevant attributes of a network element, which is discussed in {{reqattributes}}

According to use case 2, the granularity of POT may also differ. POT can be generated and recorded on a per-hop basis, or can be aggregated into one collective summary at the path level.

The most appropriate POT mechanism for each scenarios may differ-- inter-domain or intra-domain, with or without a pre-attest, per-packet or on-demand, privacy-preserving or not, etc.


### Per-hop POT header extensions

POT could be either encapsulated and passed along the original path, or sent out-of-band. It depends on the different operation modes: who should verify the POT (other elements on the path, the end host, or external security operation center (SOC)), timeliness of verification, etc.

When the POT is passed along the path, it should be encapsulated in hop-by-hop header extensions, such as IPv6 hop-by-hop options header, In-situ OAM hop-by-hop option etc. Exact size and specifications of data fields are subject to different POT mechanisms.


### Out-of-band POT extensions

For situations requiring real-time or near-real-time verification, meaning some external security operation centers (SOC) wish to have real-time visibility of the forwarding path (of an important flow, for example), out-of-band methods are needed to encapsulate and transmit POT. In this way, the SOC can verify the POT of each packet in order to make sure the forwarding is correct. For example, traffic monitoring protocols like IPFIX {{RFC7011}} or ICMP {{RFC792}}, specific management and control protocols, etc. Similarly, exact size and specifications of data fields are subject to different POT mechanisms.



# Non-Requirements {#no-req}

## Non-Requirements 1: Proof-of-Non-Transit (PONT) Mechanisms

Proof-of-Non-Transit (PONT) is a proof that a packet did NOT transit certain network elements. It is, essentially, the opposite to Req. 1 Proof-of-Transit. Certain potential user have expressed their interest on PONT for compliance or security purposes.

First of all, PONT is a non-inclusion proof, and such non-existence proof cannot be directly given.
Second, under certain circumstances, PONT can be _inferred_ from POT, especially when Ordered POT (OPOT) is enforced. For example, assume devices are perfectly secure and their behaviors completely compliant to expectations, then POT over A-B-C indicates the packet did not transit X/Y/Z. To relax the security assumptions, if the devices are remotely attested and such claim is proved by POT, then the packet _should_ only transited these trusted devices, assuming the RATS procedure is secure. The reliability of such reasoning decreases as the security level of device decreases.

NASR mailing list has agreed NOT to provide PONT mechanisms, but could provide some informational measures and conditions that could indicate PONT from POT results. For example, under xxx constraints and circumstances, if traffic passed X AND Y (device or geolocation), then it did NOT (or with a quantifiably low probability it did not) pass Z.

Since this part is research-related, NASR will work with PANRG and academia for counseling.


## Future Requirement 2: Packet Steering and Preventive Mechanisms

In the sensitive data routing use case, it is certainly necessary to know and verify the transit path of a packet using POT mechanisms. However, it might be too late to have the data already exposed to the insecure devices and risk leakage. There should be packet steering mechanisms or other preventive measures that help traffic stay in the desired path. For example, doing an egress check before sending to the next hop, preventing sending packet to a device with a non-desirable attribute.

The mailing list and side meeting has received requests to this requirement, it should fall in NASR interest, but also agreed this may not be part of the initial scope of NASR-- it is a topic to be included in further stages of NASR, in case of a rechartering.

# Commonly Asked Questions and Answers

(From side meeting and mailing list feedbacks, to be updated)

## Initially targeting for intra-domain or inter-domain scenario?

Limited domain with some trust assumptions and controls to devices will be easy to start with, but inter-domain scenario will be critical for standardization.

## Does tunneling solve the problem?

Tunnels, VPNs do not perceive the underlying network devices. Quality measurements can be done, but other detail information of bearing devices are not visible. 

## Does all nodes on the path need to compute the POT?

Whether the validation is strict or loose depends on the scenario. For example, in SFC use cases, we are only interested in verifying some important elements of interest processed the traffic.

# Contributors

This document is made possible by NASR proponents, active mailing list members and side meeting participants. Including but not limited to: Andrew Alston, Nicola Rustignoli, Michael Richardson, Mingxing Liu, Adnan Rashid and many others.

Please create **Github issues** to comment, or raise a question.
Please create new commits and **Github Pull Requests** to propose new contents.


# Security Considerations

This document has no further security considerations.

# IANA Considerations

This document has no IANA actions.



--- back


