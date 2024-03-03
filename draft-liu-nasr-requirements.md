---
title: NASR Use Case and Requirements
abbrev: nasr-req
category: info

docname: draft-liu-nasr-requirements-latest
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
  RFC7643:
  RFC7519:
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
  SAML2:
    title: Assertions and Protocols for the OASIS Security Assertion Markup Language (SAML) V2.0
    date: 2005-03
    target: https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf

  Yaar03: DOI.10.1109/SECPRI.2003.1199330

--- abstract

This document describes the use cases and requirements that guide the specification of a Network Attestation for Secure Routing framework (NASR).

--- middle

# Introduction {#intro}

This document outlines the use cases and requirements that guide the specification of a Network Attestation for Secure Routing framework (NASR).

NASR is targeted to help attest a specific network path and verify if actual forwarding result is compliant to the attested path and attributes. The components of this network path can be any combination of physical devices and links, and virtual links and virtual network functions. The target network path can correspond to a network overlay, or to an underlay supporting it, at any level in the applicable overlay recursion hierarchy.

## Note for NASR participants

This document collates and synthesizes discussion outcomes of NASR mailing list and IETF 118 path validation side meeting.

It is created to help
  1. Foster consensus among list members.
  2. Orient non-list members to NASR goals and current progress

This document may become a WG-draft but will stay as an informational draft.

# Terminology {#term}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 {{RFC2119}}, {{RFC8174}} when, and only when, they appear in all capitals, as shown here.

# Backgrounds {#back}

TBA

# Definitions {#def}

We summarize the terms discussed in the list.

* NASR: Network Attestation For Secure Routing, a proposed framework that mainly does the following:
  1. Attest to a network path
  2. Verify actual forwarding path complies with the attested path
  3. Prevent non-compliant forwarding (optional)

[Details to be added]

* Routing Security: {{RFC4593}}, {{RFC2828}}

* Path Validation: {{-PV}}

* Secure Routing: {{-SECROUT}}

* Proof-of-Transit: {{-CISCOPOT}}

* Trustworthy Path Routing: {{-TPR}}

...

# Use Cases {#usecases}


## Use Case 1: Network Path Validation

Explicit routing protocols permit explicit control over the traffic path, in order to meet certain performance, security or compliance requirements. For example, operators can use SRv6 to orchestrate a Service Function Chaining (SFC) path and provide packaged security services or compliance services. For either of them, validating the actual traffic path in the forwarding plane as an auditing measure is needed for clients and/or authorities. NASR can help operator to attest to an orchestrated path and provide verifiable forwarding proofs to help clients/authorities audit the service.

SFC is used as an (possibly canon cal) example, therefor network elements are not limited to Service Functions, and paths are not limited to a SFC path. Other devices or network functions may incorporate features (built-in security capabilities, roots of trust and attestation mechanisms, etc.) suitable to support path validation.

## Use Case 2: Verifying Path Properties

In use case 1, the orchestrated path is explicit and specific down to each network element. Sometimes, clients do not need to know every detail of the network path. Rather, clients will request the verification of a certain property within the path, such as trustworthiness, security level, geolocation, vendor characteristics, transit provider, etc. from the operator. Using NASR, the operator can orchestrate this path by selecting network elements and links with the requested properties, attest to the path, and verifiably prove to clients the path properties and that the traffic did follow this path.

In both this and the previous case, the order of the elements in the path may not be important, as the requests may be limited to a set of attributes for the path nodes, or the guarantee that traffic traversed a certain (set of) node(s).

## Use Case 3: Sensitive Data Routing

Clients from specific industries such as finance or governments have very low tolerance to data leakage. These clients require assurance that their data only travels on top of their selected leased line, MPLS VPN or SD-WAN path, and have (preferably real-time) visibility evidence or proof. Some compliance requirements also prohibit customer data escape a specific geolocation without permission. To avoid data leakage and compliance risks, some clients are willing to pay a premium for high data routing security guarantees. NASR can detect such violations and make corrections promptly, therefore supporting SLAs incorporating these guarantees.

Compared to the first and second use case, this use case also requires some preventive measures before a wrongful forwarding happens at the first place.

## Use Case 4: Ingress Filtering

Ingress Filtering techniques, such as uRPF, help prevent source IP address spoofing and denial-of-service (DoS) attacks {{RFC8704}}{{RFC5635}}. It works by validating the source IP address of a received packet by performing a reverse path lookup in FIB table, all the way to the source. If the path does not exist, the packet is dropped. NASR can be used to regularly validate the path stored in the FIB table, and tell if it continues to exist. This can potentially reduce the false negative rate.



# Requirements {#requirements}


Based on the main use-cases described in the previous section the following requirements are identified.

## Requirement 1: Proof-of-Transit (POT) Mechanisms {#reqpot}

All use cases requested public verifiability of packet transit history. Proof-of-Transit (POT) is a proof that a packet DID transit certain network elements, and it can include a verification of the order in which those elements where transited (Ordered POT, OPoO) or not. A secure POT mechanism should verifiably reflect the identity of the transited network elements and their relevant attributes, if applicable:

 - For basic POT, there is no further attribute than the identity of the transited element and, optionally, its relative position/order within the path. This is the goal of the POT mechanism defined in {{-CISCOPOT}}.

 - For extended POT, different attributes can be considered from a list of relevant ones: trustworthiness measure, available security capabilities, geolocation, vendor, etc. This needs the definition of the relevant attributes of a network element, which is discussed in {{reqattributes}}

According to use case 2, the granularity of POT may also differ. POT can be generated and recorded on a per-hop basis, or can be merged into one collective summary at the path level.

The most appropriate POT mechanism for each scenarios may differ-- inter-domain or intra-domain, with or without a pre-attest, per-packet or on-demand, privacy-preserving or not, etc.


### Per-hop POT header extensions

POT could be either encapsulated and passed along the original path, or sent out-of-band. It depends on the different operation modes: who should verify the POT (other elements on the path, the end host, or external security operation center (SOC)), timeliness of verification, etc.

When the POT is passed along the path, it should be encapsulated in hop-by-hop header extensions, such as IPv6 hop-by-hop options header, In-situ OAM hop-by-hop option etc. Exact size and specifications of data fields are subject to different POT mechanisms.


### Out-of-band POT extensions

For situations requiring real-time or near-real-time verification, meaning some external security operation center (SOC) wishes to have real-time visibility of the forwarding path, out-of-band methods are needed to encapsulate and transmit POT. In this way, the SOC can verify the POT of each packet in order to make sure the forwarding is correct. For example, traffic monitoring protocols like IPFIX {{RFC7011}} or ICMP {{RFC792}}, specific management and control protocols, etc. Similarly, exact size and specifications of data fields are subject to different POT mechanisms.


## Requirement 2: Attributes of a network element {#reqattributes}

The identity of a subject should be defined by the attributes (or claims) it owns. Attribute-defined identity is a paradigm widely accepted in SCIM {{RFC7643}}, OAuth {{RFC7519}}, SAML {{SAML2}}, etc. POT proof should reflect the identity and associated attributes, such as element type, security level, security capability it has, remotely-attested or not, vendor, deployed geolocation, current timestamp, path it is on, hop index on the path etc.

Such attributes/claims/attestation results can reuse existing specifications, for example {{-RATSEAT}}, {{-RATSRES}} in RATS WG. Some existing claims that we can reuse:

  - hwmodel (Hardware Model)
  - hwversion (Hardware Version)
  - swname (Software Name )
  - swversion (Software Version)
  - location (location)

Some new claim extensions can be made:

    elemtype
    pathid
    index
    secfunctions
    vendor
    ...

(subject to discussion, add, change)

NASR could work closely with RATS on the standardization of above attributes and means of proving them.


## Requirement 3: Path Attestation Procedures

After a path is selected, it should be

  1. Committed to prevent changes,
  2. Publicized for common referencing and retrieval.

The stored path should contain this information: unique ID (within a domain), all network elements on the path, and attributes of them. (Schemas may vary depending on scenarios)


TBA


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

## Why not use static routing?

Static routing severely limits the scalability and flexibility for performance optimizations and reconfigurations. Flexible orchestration of paths will be prohibited. Also, even when static routing is used, we still need proof of transit for compliance checks.

## Initially targeting for intra-domain or inter-domain scenario?

Limited domain with some trust assumptions and controls to devices will be easy to start with. Then we can go do the interdomain.

## Does tunneling solve the problem?


## Does all nodes on the path need to compute the POT?

Whether the validation is strict or loose depends on the scenario. For example, in SFC use cases, we are only interested in verifying some important elements of interest processed the traffic.

# Contributors

This document is made possible by NASR proponents, active mailing list members and side meeting participants. Including but not limited to: Andrew Alston, Meiling Chen, Nicola Rustignoli, Michael Richardson, Adnan Rashid and many others.

Please create **Github issues** to comment, or raise a question.
Please create new commits and **Github Pull Requests** to propose new contents.


# Security Considerations

This document has no further security considerations.

# IANA Considerations

This document has no IANA actions.



--- back


