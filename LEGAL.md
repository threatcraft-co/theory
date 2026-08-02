# THEORY — Regional Legal Addenda

**Threatcraft Holdings LLC dba Threatcraft Co.**
Last updated: March 2026

This document contains jurisdiction-specific legal provisions that supplement
the main `DISCLAIMER.md`. Users in the applicable regions should read both
documents. In the event of conflict, the more protective provision applies.

---

# PART I — United States Federal

## US.1 Computer Fraud and Abuse Act (CFAA)

THEORY is not designed, intended, or authorized for use in facilitating
unauthorized access to computer systems as defined under 18 U.S.C. § 1030
(the Computer Fraud and Abuse Act). Indicators of compromise, IP addresses,
domains, and other technical data surfaced by THEORY are provided for
**defensive research and authorized security assessment purposes only**.

Using THEORY outputs to access, damage, or obtain information from any
computer system without authorization may constitute a federal criminal
offense. Threatcraft Co. expressly disavows any use of this tool that
violates the CFAA or any equivalent state computer crime statute.

## US.2 Economic Espionage Act

THEORY aggregates publicly available threat intelligence. It is not a vehicle
for obtaining, transferring, or receiving trade secrets as defined under
18 U.S.C. §§ 1831–1839. Users may not use THEORY to facilitate economic
espionage or theft of trade secrets on behalf of any foreign government,
instrumentality, or agent.

## US.3 Export Controls (EAR / ITAR)

Certain cybersecurity tools and technical data may be subject to Export
Administration Regulations (EAR) administered by the U.S. Department of
Commerce Bureau of Industry and Security, or to International Traffic in
Arms Regulations (ITAR) administered by the U.S. Department of State.

THEORY is open-source software published in accordance with the EAR
License Exception for publicly available encryption source code (EAR
§ 742.15(b)). Users are responsible for determining whether their specific
use of THEORY or its outputs is subject to export control restrictions in
their jurisdiction.

## US.4 Stored Communications Act (SCA)

THEORY does not access, store, or transmit electronic communications or
stored data from third-party systems. Any user who uses THEORY outputs to
facilitate unauthorized access to stored communications may be subject to
liability under 18 U.S.C. §§ 2701–2712.

---

# PART II — European Union (GDPR)

## EU.1 Scope

This section applies to users located in the European Economic Area (EEA)
and to any processing of personal data of EEA residents, regardless of
where THEORY is operated from.

## EU.2 Role of the Parties

**Threatcraft Co. is not a data controller or data processor** in respect
of end users' use of THEORY. THEORY is a locally executed tool — Threatcraft
Co. does not receive, store, or process any personal data entered by users
or returned by third-party APIs in connection with any specific user's session.

Users who deploy THEORY in an organizational context and process personal
data using its outputs are independently responsible for their own GDPR
compliance obligations as data controllers.

## EU.3 Personal Data in Threat Intelligence (Recital 49 Basis)

Some data surfaced by THEORY — including email addresses appearing in IOC
tables — may constitute personal data under Article 4(1) of the GDPR.

The processing of personal data in the context of cybersecurity research
and threat intelligence is recognized as a legitimate purpose under:

- **GDPR Article 6(1)(f)** — legitimate interests of the data controller
  or a third party, where those interests are not overridden by the rights
  of the data subject
- **GDPR Recital 49** — which explicitly recognizes network and information
  security as a legitimate interest, including "the prevention of
  unauthorised access to electronic communications networks and malicious
  code distribution and stopping 'denial of service' attacks"

Users relying on this basis should document their legitimate interests
assessment (LIA) in accordance with guidance from their relevant supervisory
authority.

## EU.4 Data Minimization

THEORY is designed with data minimization principles in mind:

- No user query data is transmitted to or stored by Threatcraft Co.
- API keys and credentials remain local to the user's environment
- Cached data is stored locally on the user's machine
- No telemetry, usage tracking, or analytics data is collected by the tool

## EU.5 Third-Party API Processing

When users configure THEORY with third-party API keys (OTX, Anthropic,
OpenAI, GitHub), data may be transmitted to those providers. Users are
responsible for ensuring that any such transmission complies with their
own GDPR obligations and the terms of service of those providers.

Threatcraft Co. is not responsible for the data processing practices of
any third-party API provider.

## EU.6 Data Subject Rights

As Threatcraft Co. does not process personal data of THEORY users,
data subject rights requests (access, rectification, erasure, portability)
under Articles 15–20 of the GDPR are not applicable to Threatcraft Co.
in respect of THEORY usage.

Users who have concerns about personal data appearing in threat intelligence
sources (such as email addresses in OTX pulses) should contact the relevant
data controller — the third-party source — directly.

## EU.7 Cross-Border Data Transfers

THEORY may transmit data to API providers located outside the EEA, including
in the United States. Users are responsible for ensuring that any such
transfers comply with Chapter V of the GDPR, including the use of appropriate
safeguards such as Standard Contractual Clauses (SCCs) where required.

## EU.8 Supervisory Authority

Users in the EU have the right to lodge a complaint with their relevant
national data protection supervisory authority if they believe their rights
under the GDPR have been violated in connection with the use of THEORY.

---

# PART III — United Kingdom

## UK.1 UK GDPR

The United Kingdom has implemented its own version of the GDPR following
its departure from the European Union (the "UK GDPR," incorporated into
UK law by the Data Protection Act 2018). The provisions of Part II of this
document apply equally to users in the United Kingdom, with references to
"GDPR" read as references to "UK GDPR" and references to the "EEA" read
as including the United Kingdom.

## UK.2 Computer Misuse Act 1990

THEORY is not designed or intended for use in facilitating unauthorized
access to computer material as defined under Section 1 of the Computer
Misuse Act 1990, or unauthorized acts with intent to impair computer
operation under Section 3. Users in the United Kingdom must ensure that
any use of THEORY outputs in security research or penetration testing is
conducted with explicit written authorization from the relevant asset owner.

## UK.3 Investigatory Powers Act 2016

THEORY does not intercept communications or conduct bulk data collection.
Nothing in the tool's operation is intended to engage with or circumvent
the Investigatory Powers Act 2016.

## UK.4 Information Commissioner's Office (ICO)

Users in the United Kingdom have the right to lodge a complaint with the
Information Commissioner's Office (ICO) at ico.org.uk if they believe
their data protection rights have been violated.

---

# PART IV — General International Provisions

## INT.1 Compliance with Local Law

Users are responsible for determining whether their use of THEORY complies
with the laws of their jurisdiction. THEORY is made available globally as
open-source software — Threatcraft Co. makes no representation that use of
the tool is appropriate, lawful, or permitted in any specific jurisdiction.

## INT.2 Sanctions Compliance

Users must not use THEORY in violation of applicable sanctions regimes,
including those administered by the U.S. Office of Foreign Assets Control
(OFAC), the EU, or the UN Security Council. This includes using THEORY
to provide services or technical assistance to sanctioned persons, entities,
or jurisdictions.

## INT.3 NIS2 Directive (EU)

Organizations subject to the EU Network and Information Security Directive 2
(NIS2, Directive (EU) 2022/2555) that use THEORY as part of their security
operations are solely responsible for ensuring that their use of the tool
and its outputs complies with their obligations under NIS2, including
incident reporting, risk management, and supply chain security requirements.

## INT.4 Researcher Safe Harbor

Threatcraft Co. recognizes the importance of good-faith security research.
Nothing in this disclaimer is intended to prevent or discourage:

- Responsible disclosure of vulnerabilities discovered in the course of
  legitimate security research
- Publication of threat intelligence research that references THEORY outputs
- Academic study of threat actor TTPs, malware, or attack infrastructure

Users engaged in good-faith security research who discover that a third-party
source ingested by THEORY contains false, manipulated, or harmful data are
encouraged to report their findings to the relevant source and, where
appropriate, to Threatcraft Co. via the project's GitHub repository.

---

## Contact

For legal inquiries related to THEORY:

**Threatcraft Holdings LLC dba Threatcraft Co.**
GitHub: github.com/threatcraft-co/theory
Contact: threatcraft@proton.me

*This document does not constitute legal advice. Users with jurisdiction-
specific legal questions should consult qualified legal counsel in their
applicable jurisdiction.*
