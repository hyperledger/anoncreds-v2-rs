// ------------------------------------------------------------------------------
import {defineCryptoInterfaceWith, VCP} from '../api';
import { describeValue, IndexSignature3Level } from '../util';
// ------------------------------------------------------------------------------
import {TestData} from './TestData'
import {Util} from './Util'
// ------------------------------------------------------------------------------
import * as GENERATED from 'VCP';
// ------------------------------------------------------------------------------

export enum SigType {
  Blinded    = "Blinded",
  NonBlinded = "NonBlinded"
}

export class X {
  static readonly port : string = "8080";
  readonly zkpLib      : string;
  readonly sigType     : SigType;
  readonly ci          : VCP;
  dSard                : GENERATED.SignatureAndRelatedData = { signature: "", values: [], accumulatorWitnesses: {}}
  sSard                : GENERATED.SignatureAndRelatedData = { signature: "", values: [], accumulatorWitnesses: {}}
  shared               : Map<string, GENERATED.SharedParamValue> = new Map();
  reqs                 : Map<string, GENERATED.CredentialReqs>   = new Map();
  credD                : GENERATED.CredentialReqs = { signerLabel: "", disclosed: [], inAccum: [], notInAccum: [],
                                                      inRange: [], encryptedFor: [], equalTo: []};

  credS                : GENERATED.CredentialReqs = { signerLabel: "", disclosed: [], inAccum: [], notInAccum: [],
                                                      inRange: [], encryptedFor: [], equalTo: []};

  private constructor(z: string, st: SigType) {
    this.zkpLib  = z;
    this.sigType = st;
    this.ci      = defineCryptoInterfaceWith(z, X.port);
  }

  static async create(
    z  : string,
    st : SigType
  ) : Promise<X> {
    const x = new X(z, st);
    const [dSard, sSard, shared] = await x.doCreateSharedAndSigs(x);
    x.shared = shared;
    x.reqs   = TestData.proofReqs();
    x.dSard  = dSard;
    x.sSard  = sSard;
    x.credD  = x.reqs.get(TestData.DL)!;
    x.credS  = x.reqs.get(TestData.SUB)!;
    return x;
  }

  private async doCreateSharedAndSigs(
    x : X,
  ) : Promise<[GENERATED.SignatureAndRelatedData,
               GENERATED.SignatureAndRelatedData,
               Map<string, GENERATED.SharedParamValue>]> {
    Util.sop("ClaimTypes D", TestData.dCTs(x.zkpLib));
    Util.sop("ClaimTypes S", TestData.sCTs(x.zkpLib));

    // Issuer
    return X.createSignerDataAndSignatures(x).then(
      ([dSignerData, sSignerData, dSig, sSig]) => {
      Util.sop("dSignerData D", dSignerData);
      Util.sop("sSignerData S", sSignerData);

      Util.sop("dVals", TestData.dVals());
      Util.sop("sVals", TestData.sVals());

      Util.sop("dSig", dSig);
      Util.sop("sSig", sSig);

      const dSard : GENERATED.SignatureAndRelatedData = {
        signature            : dSig,
        values               : TestData.dVals(),
        accumulatorWitnesses : {},
      };
      const sSard : GENERATED.SignatureAndRelatedData = {
        signature            : sSig,
        values               : TestData.sVals(),
        accumulatorWitnesses : {},
      };

      // Verifier
      const { signerPublicData : dPub } = dSignerData;
      const { signerPublicData : sPub } = sSignerData;
      const shared = TestData.shared(dPub, sPub);

      Util.sop("shared", shared);

      return [dSard, sSard, shared];

    });
  }

  static async createSignerDataAndSignatures(
    x : X
  ) : Promise<[GENERATED.SignerData, GENERATED.SignerData, string, string]> {
    let dSignerData = undefined;
    let sSignerData = undefined;
    let dSig        = undefined;
    let sSig        = undefined;
    if (x.sigType == SigType.NonBlinded) {
      dSignerData = await x.ci.createSignerData(0, TestData.dCTs(x.zkpLib), []);
      sSignerData = await x.ci.createSignerData(1, TestData.sCTs(x.zkpLib), []);
      dSig = await x.ci.sign(0, dSignerData, TestData.dVals());
      sSig = await x.ci.sign(0, sSignerData, TestData.sVals());
    } else {
      dSignerData = await x.ci.createSignerData(0, TestData.dCTs(x.zkpLib), TestData.DL_BLINDED_INDICES);
      sSignerData = await x.ci.createSignerData(1, TestData.sCTs(x.zkpLib), TestData.SUB_BLINDED_INDICES);
      const dBlindSigningInfo = await x.ci.createBlindSigningInfo(
        0, dSignerData.signerPublicData, TestData.dBlindedIndicesAndVals());
      const sBlindSigningInfo = await x.ci.createBlindSigningInfo(
        0, sSignerData.signerPublicData, TestData.sBlindedIndicesAndVals());
      const dBlindSignature   = await x.ci.signWithBlindedAttributes(
        0, dSignerData, TestData.dNonBlindedIndicesAndVals(), dBlindSigningInfo.blindInfoForSigner);
      const sBlindSignature   = await x.ci.signWithBlindedAttributes(
        0, sSignerData, TestData.sNonBlindedIndicesAndVals(), sBlindSigningInfo.blindInfoForSigner);
      dSig                    = await x.ci.unblindBlindedSignature(
        TestData.dCTs(x.zkpLib), TestData.dBlindedIndicesAndVals(),
        dBlindSigningInfo.infoForUnblinding, dBlindSignature);
      sSig                    = await x.ci.unblindBlindedSignature(
        TestData.sCTs(x.zkpLib), TestData.sBlindedIndicesAndVals(),
        sBlindSigningInfo.infoForUnblinding, sBlindSignature);
    }
    return [ dSignerData, sSignerData, dSig, sSig ];

  }

  public static doCreateProof(
    x : X
  ) : Promise<GENERATED.WarningsAndDataForVerifier> {
    const sigsAndRelatedData = new Map<string, GENERATED.SignatureAndRelatedData>();
    sigsAndRelatedData.set(TestData.DL , x.dSard);
    sigsAndRelatedData.set(TestData.SUB, x.sSard);
    return x.ci.createProof(x.reqs, x.shared, sigsAndRelatedData, TestData.NONCE);
  }

  // Verifier
  public static doVerifyProof(
    x               : X,
    dfv             : GENERATED.DataForVerifier,
    decryptRequests : IndexSignature3Level<GENERATED.DecryptRequest>,
  ) : Promise<GENERATED.WarningsAndDecryptResponses> {
    return x.ci.verifyProof(x.reqs, x.shared, dfv, decryptRequests, TestData.NONCE);
  }
}

