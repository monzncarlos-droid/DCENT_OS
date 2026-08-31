# Nano 3 USB-C power-chain qualification

**Record state:** two candidate assemblies defined; no part approved
**First-party reference candidate:** Canaan-bundled `TP14A1` with captive
USB-C output cable and a detachable regional AC cord
**Third-party candidate:** Plugable `PS-EPR-140C1`, North American direct-plug
variant, plus Plugable `USB4-240W-1M`, passive 1 m USB-C to USB-C
**Safety claim:** none. This worksheet does not authorize production use,
unattended operation, or native takeover.

The operator-reported Reddit experience is useful for candidate discovery only.
The discussions are not unanimous acceptance evidence: they include a reported
successful Plugable-plus-240-W-cable pairing, but also cable-dependent high-mode
operation, rejected adapters, very hot connectors, and melted USB-C interfaces.
That mixed field record strengthens the exact-specimen/no-substitution rule; it
does not qualify any charger or cable. Plugable's claim that this charger runs
cooler than an Apple comparison unit is also not a Nano 3 thermal result.

## 1. Controlled candidates

| Item | Officially published candidate data | Qualification status |
|---|---|---|
| Canaan first-party reference assembly | An independent teardown of the original bundled adapter identifies model `TP14A1`; label input `100-240 Vac, 50/60 Hz, 1.8 A max`; PD outputs 5/9/12/15 V at 3 A and 20/28 V at 5 A; captive USB-C cable about 1.21 m. Analyzer capture reports PD 3.1/EPR and about 27.24 V, 4.69 A, 127.68 W in full mode. Canaan separately publishes the Nano 3 as 28 V input, 140 W maximum. | `REFERENCE_CANDIDATE_NOT_APPROVED`; physical authenticity, exact nameplate, safety listing, cable condition, PDO/RDO, and thermal qualification remain mandatory |
| Marketplace listing pasted by operator | Claims “genuine Canaan,” 140 W, USB-C, 240 V input, 12 Vdc/11.67 A output, Molex, laptop compatibility, two-pin main connector, and Type-B three-pin plug. Those taxonomy fields are internally inconsistent and conflict with the 28 V/5 A EPR contract. | `REJECT_AS_ELECTRICAL_IDENTITY`; retain only as purchase-source metadata until the physical adapter label and PD capture identify the specimen |
| Charger | Plugable `PS-EPR-140C1`; UPC/GTIN `819927012948`; one USB-C PD 3.1 EPR port; advertised outputs 5 V/3 A, 9 V/3 A, 15 V/3 A, 20 V/5 A, and 28 V/5 A | `CANDIDATE_NOT_APPROVED` |
| Charger input | Direct region-specific AC plug; exact voltage, frequency, current, certification-file identity, hardware revision, lot, and serial must be transcribed from the purchased specimen's nameplate | `TBD_PHYSICAL_NAMEPLATE_AND_CERTIFICATE_MATCH` |
| Charger safety evidence | Plugable claims UL, FCC, and DOE certifications. UL Product iQ lists model `PS-EPR-140C1` under external-power-supply certificate holder Dongguan CE Link Limited. The specimen and regional variant still require an exact label/listing match. | `TBD_SPECIMEN_LISTING_MATCH` |
| Cable | Plugable `USB4-240W-1M`; UPC/GTIN `819927012894`; passive 1 m; advertised 48 V/5 A, 240 W EPR and 40 Gbit/s; Plugable claims USB-IF certification | `CANDIDATE_NOT_APPROVED` |
| Cable certification | USB-IF requires a certified 240 W cable/logo to pass the applicable PD 3.1 EPR and Type-C cable tests and be posted to its Integrators List. The public product data was checked for the exact consumer SKU on 2026-08-22 and did not expose a match. Absence is not proof of non-certification, but the vendor claim alone is insufficient. Capture the specimen e-marker identity and obtain a matching TID/XID or manufacturer certification record. | `TBD_E_MARKER_AND_USB_IF_RECORD_MATCH` |
| Nano 3 sink contract | Canaan publishes 28 V input and 140 W maximum, and its support note explicitly says the Nano 3 requires a high-spec PD cable supporting 28 V/5 A. Canaan describes actual load in its 140 W adapter test as about 127 W. These are vendor requirements, not a capture of this unit's Request Data Object or proof that it remains at that PDO. | `TBD_COLD_WARM_PD_CAPTURE` |

`TP14A1` plus its captive USB-C lead is one inseparable candidate assembly.
Do not add or substitute a detachable USB-C cable on that lane. Likewise,
`PS-EPR-140C1` and `USB4-240W-1M` identify one third-party candidate assembly,
not interchangeable classes. A different cord, cable, cable length, charger
region, revision, marketplace bundle, or visually similar unit is a
substitution.

## 2. Specimen record

Complete one record for every charger/cable pair. Attach clear nameplate,
packaging, connector, cable-marking, and e-marker-reader photographs.

| Field | Recorded value |
|---|---|
| Qualification record ID / date / operator | `TBD` |
| Candidate lane | `TBD`; exactly one of `CANAAN_TP14A1_CAPTIVE` or `PLUGABLE_PS-EPR-140C1_USB4-240W-1M` |
| Charger asset ID / exact manufacturer / model / SKU / UPC | `TBD`; Canaan lane must physically prove Canaan / `TP14A1`; Plugable lane must be `PS-EPR-140C1` / `819927012948` |
| Charger input nameplate, verbatim (VAC, Hz, A) | `TBD_PHYSICAL_TRANSCRIPTION` |
| Charger output nameplate, verbatim | `TBD_PHYSICAL_TRANSCRIPTION` |
| Charger serial, lot/date code, hardware revision, country of manufacture | `TBD` |
| Charger certification marks and exact UL file/listing correlation | `TBD` |
| Purchase source, invoice, and authenticity evidence | `TBD` |
| Output-cable topology and asset identity | `TBD`; Canaan lane must document the intact captive lead; Plugable lane must be detachable `USB4-240W-1M` / `819927012894` / 1 m |
| Cable jacket and connector markings, verbatim | `TBD` |
| Cable package 240 W certified logo and traceable product record | `TBD` |
| E-marker raw VDOs; manufacturer/Vendor ID; product ID; XID/TID; current and voltage capability | `TBD_E_MARKER_CAPTURE` |
| PD analyzer model/serial/firmware/calibration due date | `TBD`; must be rated for at least 48 V/5 A EPR |
| AC power analyzer and temperature-instrument identities/calibration | `TBD` |
| Nano 3 asset ID, firmware, mining profile, and maximum qualified load | `TBD`; distinguish 65 W, 100 W, and 140 W modes and bind each accepted mode to its measured Request/PDO |
| Qualified AC input and ambient range | `TBD_AFTER_NAMEPLATE_AND_DEPLOYMENT_REVIEW` |

Any illegible, inconsistent, missing, or untraceable entry is a refusal, not a
waiver.

## 3. Test boundary and instrumentation

The independent interlock remains on **AC upstream of the charger**:

```text
branch protection -> K1 NO -> K2 NO -> controlled AC receptacle
                                             |
                        +--------------------+--------------------+
                        |                                         |
            TP14A1 + captive USB-C                 PS-EPR-140C1 charger
              (first-party lane)                             |
                        |                           USB4-240W-1M cable
                        |                                         |
                        +------------------ Nano 3 ---------------+
```

The diagram shows alternative qualification lanes, never simultaneous or
intermixed parts. A production record binds exactly one complete lane.

Do not add an inline DC switch, extension, magnetic adapter, hub, power meter,
or USB-C coupler to the production chain. The qualification PD analyzer is
temporary test equipment; repeat a final thermal run without it. The controlled
receptacle must accept and retain the 340 g direct-plug charger without damaged
contacts or unsafe mechanical load. Protective earth and the independent
24 V safety supply remain outside the switched load path as specified in
`WIRING.md`.

Use synchronized, calibrated logging for:

- AC RMS voltage/current/power and K1/K2 state;
- USB-C VBUS voltage/current/power and every PD packet/state transition;
- ambient, charger case hot spot, charger USB-C receptacle/plug, both cable
  connector shells/strain reliefs, cable midpoint, and Nano 3 USB-C receptacle;
- Nano boot, mining/load state, and unexpected resets; and
- fixture fan, temperature, and custody channels required by the main
  interlock qualification.

Temperature attachment must not insulate a hot spot, loosen a connector, or
create an electrical path. Record sampling rates, instrument uncertainty, and
photographs of every sensor location.

## 4. Procedure

1. **Quarantine and identify.** Do not energize until the specimen record is
   complete. For `TP14A1`, obtain purchase/authenticity evidence, transcribe and
   photograph the complete adapter label and detachable AC cord, and inspect
   the captive USB-C lead end-to-end. For the Plugable lane, compare charger
   markings to the current official Plugable page and UL listing, then read the
   cable e-marker at both plug orientations and correlate it with a current
   USB-IF/manufacturer certification record. Marketplace attribute tables are
   never accepted as an electrical nameplate.
2. **Establish limits before the Nano test.** A qualified reviewer records the
   deployment AC range, connector/cable/charger temperature limits, instrument
   uncertainty, and required margin. Plugable's public page does not publish an
   acceptable Nano 3 case-temperature limit, so the thermal gate remains open
   until written component limits or a reviewed standard-based limit exists.
3. **Capture source capabilities.** With an EPR-rated analyzer, save the raw
   Source_Capabilities, EPR entry, Nano Request, Accept, PS_RDY, VBUS, and current
   sequence. Confirm the cable advertises the required 5 A/EPR capability.
   Determine the Nano's actual Request/PDO from the trace. At the intended
   maximum mode, reconcile it with Canaan's documented 28 V/5 A requirement;
   a different or unstable result is a refusal, not permission to infer power
   from the charger label. Qualify 65 W and 100 W modes separately if shipped.
4. **Cold negotiation.** From fully de-energized/ambient-stabilized state, run
   at least ten AC starts in each cable-end direction and connector orientation
   used by the controlled assembly. Every run must reach the same reviewed PDO
   without loops, fallback, over-current, undervoltage, disconnect, or boot
   reset. Save raw captures, not screenshots alone.
5. **Warm negotiation.** At maximum qualified Nano load, operate until thermal
   slope is no more than 1 degrees C per hour for one hour. Then perform at least
   ten attended AC cut/manual-re-arm cycles using the qualified off and startup
   intervals. The Request/PDO and boot result must remain inside the cold-test
   acceptance envelope.
6. **Sustained thermal run.** At the maximum qualified load, AC input, and
   ambient, log until the same thermal-equilibrium criterion is met and then for
   at least two additional hours, with a minimum total run of eight hours. No
   measured point may exceed its reviewed limit minus uncertainty and margin.
   There must be no PD renegotiation/dropout, VBUS instability, odor,
   discoloration, softened insulation, connector movement, or deformation.
   This run does not replace the longer system production soak.
7. **Remove analyzer and repeat.** Repeat the worst-case sustained run with the
   exact controlled charger/cable path and temperature sensors but without the
   inline PD analyzer. Compare electrical and thermal results for analyzer
   insertion bias.
8. **Cutoff correlation.** Trip each independent interlock input while logging
   AC, K1/K2, VBUS, Nano load/hash cessation, and passive thermal coast-down.
   Power must be removed by the AC contactors and require manual reset. This
   power-chain result cannot by itself close the separate hash-stop,
   coast-down, heartbeat, or native-takeover gates.
9. **Inspect and archive.** After cooling, inspect both receptacles, both cable
   plugs, the charger pins/case, and the cable. Hash and archive raw traces,
   photographs, analyzer configuration, calibration records, and the completed
   worksheet under the release evidence ID.

## 5. Acceptance and substitution control

Each assembly remains rejected until all of the following are signed:

- the physical input nameplate covers the qualified AC source and matches the
  exact safety listing/region;
- the Canaan lane has an intact, identity-bound captive lead, or the Plugable
  lane's e-marker and current certification record resolve to the controlled
  `USB4-240W-1M` specimen, 5 A EPR capability, and 240 W cable identity;
- the Nano's accepted cold and warm PDO/RDO are captured and stable in every
  required orientation and restart case;
- connector, cable, charger, and Nano receptacle temperatures pass documented
  limits with uncertainty and engineering margin;
- sustained electrical, mechanical inspection, AC-cutoff, and system safety
  gates pass; and
- an electrical-safety reviewer approves the exact record.

Production records bind the candidate lane, charger model/SKU, regional
variant, hardware revision, serial/lot, certification file, output-cable
topology and identity, jacket/connector markings, applicable e-marker VDOs,
purchase source, and approved evidence hashes. Changing any of
those fields—or accepting a generic "140 W" charger or "240 W" cable—sets the
assembly back to `CANDIDATE_NOT_APPROVED` and requires the full electrical, PD,
thermal, cutoff, and inspection sequence again.

## 6. Sources reviewed 2026-08-22

- Charging Head Network/ChargerLAB,
  [Avalon Nano 3 original 140 W adapter TP14A1 teardown](https://www.chongdiantou.com/archives/342931.html)
  (independent photographs/transcription of model, label, captive cable,
  PD/PPS/EPR capabilities, and a full-mode 27.24 V/4.69 A observation; useful
  reference evidence, not a substitute for authenticating the held specimen).

- Plugable, [PS-EPR-140C1 product page](https://plugable.com/products/ps-epr-140c1)
  (SKU, UPC, single-port PD 3.1 EPR, dimensions/weight, certifications claimed,
  advertised outputs).
- Plugable Knowledge Base,
  [PS-EPR-140C1 supported voltage and amperage](https://kb.plugable.com/power-devices/what-is-the-supported-voltage-and-amperage-range-for-the-ps-epr-140c1)
  (5/9/15/20/28 V PDO claims and 28 V EPR condition).
- UL Product iQ,
  [external power supplies listing containing PS-EPR-140C1](https://productiq.ulprospector.com/en/profile/5720591/external%20power%20supplies.2647470?page=38&term=External+Power+Supplies)
  (exact model listed under Dongguan CE Link Limited).
- Plugable, [USB4-240W-1M product page](https://plugable.com/products/usb4-240w-1m)
  (SKU, UPC, passive 1 m, 48 V/5 A, 240 W EPR, and USB-IF certification claim).
- Reddit r/BitcoinMining,
  [Avalon Nano 3 alternative PSU](https://www.reddit.com/r/BitcoinMining/comments/1dt5zkf/)
  (mixed operator reports; candidate discovery only)
- Reddit r/BitcoinMining,
  [Avalon Nano 3 and 3S connector/adapter heat reports](https://www.reddit.com/r/BitcoinMining/comments/1jqlung/)
  (unverified field-failure reports; hazard discovery only)
- USB-IF, [Cables and Connectors](https://www.usb.org/cable_connector) and
  [USB Type-C Cable Power Rating Logo Usage Guide](https://www.usb.org/sites/default/files/usb_type-c_cable_power_rating_logo_usage_guidelines_020222.pdf)
  (240 W marking and certification/Integrators List requirements).
- USB-IF, [Certified Product List](https://www.usb.org/products) and its public
  data endpoint `/vtm-products/v1/all` (scope of the public list and exact-SKU
  search noted above).
- Canaan, [Avalon Nano 3 product page](https://shop.canaan.io/products/avalon-nano-3)
  (28 V input, 140 W maximum, and selectable 65/100/140 W operating modes).
- Canaan Support,
  [Progress on non-supported adapter issue](https://support.canaan.io/en-us/knowledgebase/article/KA-01244)
  (explicit 28 V/5 A cable requirement and failure behavior when adapter power
  or cable capability is inadequate).
- Canaan Help Center,
  [Nano 3 adapter temperature and safety discussion](https://help.canaan.io/hc/en-us/articles/39087855167257-Technical-Discussion-on-Temperature-Performance-and-Safety-of-Avalon-Nano3-Power-Adapter)
  (140 W/28 V/5 A adapter rating, about 127 W stated actual load, 0-40 C
  operating range, and vendor thermal/ripple test context; not a substitute
  for qualification of the Plugable candidate).
