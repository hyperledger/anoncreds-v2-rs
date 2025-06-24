// ------------------------------------------------------------------------------
import {Util} from './Util';
// ------------------------------------------------------------------------------
import * as GENERATED from 'VCP';
// ------------------------------------------------------------------------------

export class TestData {

  static readonly AUTH_LABEL            : string   = "authorityPublic";
  static readonly NONCE                 : string   = "nonce-from-typescript";

  // --------------------------------------------------

  static readonly DL                    : string   = "DL";
  static readonly DL_SIGNER_PUBLIC      : string   = "dlSignerPublic";
  static readonly DL_REVEALED           : number[] = [0];

  static readonly DL_ACC                : string   = "dlAcc";
  static readonly DL_ACC_INDEX          : number   = 4;
  static readonly DL_ACC_INDEX_STR      : string   = "4";
  static readonly DL_MPK                : string   = "dlMpk";
  static readonly DL_APD                : string   = "dlAccPublicData";
  static readonly DL_HOLDER_ID          : string   = "dlHolderID";
  static readonly DL_ACC_SEQ_NUM        : number   = 1;
  static readonly DL_ACC_SEQ_NUM_LABEL  : string   = "DL_ACC_SEQ_NUM_LABEL";
  static readonly DL_ACC_MEM_VALUE      : string   = "abcdef0123456789abcdef0123456789";

  static readonly DL_RPPK               : string   = "dlRppk";
  static readonly DL_IN_RANGE_INDEX     : number   = 1;
  static readonly DL_RANGE_MIN          : string   = "dlMinBDdays";
  static readonly DL_RANGE_MAX          : string   = "dlMaxBDdays";

  // --------------------------------------------------

  static readonly SUB                   : string   = "sub";
  static readonly SUB_SIGNER_PUBLIC     : string   = "subSignerPublic";
  static readonly SUB_REVEALED          : number[] = [0];

  static readonly SUB_ACC               : string   = "subAcc";
  static readonly SUB_ACC_INDEX         : number   = 1;
  static readonly SUB_ACC_INDEX_STR     : string   = "1";
  static readonly SUB_MPK               : string   = "subMpk";
  static readonly SUB_APD               : string   = "subAccPublicData";
  static readonly SUB_HOLDER_ID         : string   = "subHolderID";
  static readonly SUB_ACC_SEQ_NUM       : number   = 1;
  static readonly SUB_ACC_SEQ_NUM_LABEL : string   = "SUB_ACC_SEQ_NUM_LABEL";
  static readonly SUB_ACC_MEM_VALUE     : string   = "aaaabcdef0123456789abcdef0123456";

  static readonly SUB_RPPK              : string   = "subRppk";
  static readonly SUB_IN_RANGE_INDEX    : number   = 2;
  static readonly SUB_RANGE_MIN         : string   = "subMinValiddays";
  static readonly SUB_RANGE_MAX         : string   = "subMaxValiddays";

  // --------------------------------------------------

  static dVals() : GENERATED.DataValue[] {
    return [
        Util.mkDVText("CredentialMetadata (fromList [(\"purpose\",DVText \"DriverLicense\"),(\"version\",DVText \"1.0\")])")
      , Util.mkDVInt(37852)
      , Util.mkDVText("123-45-6789")
      , Util.mkDVInt(180)
      , Util.mkDVText(this.DL_ACC_MEM_VALUE)
    ];
  }

  public static DL_BLINDED_INDICES = [1,2,3,4];

  public static dBlindedIndicesAndVals() : GENERATED.CredAttrIndexAndDataValue[] {
    return this.getBlinded(this.dVals(), this.DL_BLINDED_INDICES);
  }

  static dNonBlindedIndicesAndVals() : GENERATED.CredAttrIndexAndDataValue[] {
    return this.getNonBlinded(this.dVals(), this.DL_BLINDED_INDICES);
  }

  static dCTs(_zkpLib: string) : GENERATED.ClaimType[] {
    return [
        GENERATED.ClaimType.CtText
      , GENERATED.ClaimType.CtInt
      , GENERATED.ClaimType.CtEncryptableText
      , GENERATED.ClaimType.CtInt
      , GENERATED.ClaimType.CtAccumulatorMember
    ];
  }

  // --------------------------------------------------

  static sVals(): GENERATED.DataValue[] {
    return [
        Util.mkDVText("CredentialMetadata (fromList [(\"purpose\",DVText \"MonthlySubscription\"),(\"version\",DVText \"1.0\")])")
      , Util.mkDVText(this.SUB_ACC_MEM_VALUE)
      , Util.mkDVInt(49997)
      , Util.mkDVText("123-45-6789")
    ];
  }

  public static SUB_BLINDED_INDICES = [1,2,3];

  static sBlindedIndicesAndVals() : GENERATED.CredAttrIndexAndDataValue[] {
    return    this.getBlinded(this.sVals(), this.SUB_BLINDED_INDICES);
  }

  static sNonBlindedIndicesAndVals() : GENERATED.CredAttrIndexAndDataValue[] {
    return this.getNonBlinded(this.sVals(), this.SUB_BLINDED_INDICES);
  }

  static sCTs(_zkpLib: string) : GENERATED.ClaimType[] {
    return [
        GENERATED.ClaimType.CtText
      , GENERATED.ClaimType.CtAccumulatorMember
      , GENERATED.ClaimType.CtInt
      , GENERATED.ClaimType.CtEncryptableText
    ];
  }

  // --------------------------------------------------

  static proofReqs() : Map<string, GENERATED.CredentialReqs> {
    const reqs = new Map<string, GENERATED.CredentialReqs>();
    reqs.set(this.DL,  this.initCred(this.DL_SIGNER_PUBLIC));
    reqs.set(this.SUB, this.initCred(this.SUB_SIGNER_PUBLIC));
    return reqs
  }

  // --------------------------------------------------

  static initCred(signerLabel : string) : GENERATED.CredentialReqs {
    return {
      signerLabel  : signerLabel,
      disclosed    : [],
      inAccum      : [],
      notInAccum   : [],
      inRange      : [],
      encryptedFor : [],
      equalTo      : []
    }
  }

  // --------------------------------------------------

  static shared(
    dSignerPublicData: GENERATED.SignerPublicData,
    sSignerPublicData: GENERATED.SignerPublicData
  ) : Map<string, GENERATED.SharedParamValue> {
    let shared = new Map<string, GENERATED.SharedParamValue>();
    shared.set(this.DL_SIGNER_PUBLIC,  Util.mkSPVOneText(JSON.stringify(dSignerPublicData)));
    shared.set(this.SUB_SIGNER_PUBLIC, Util.mkSPVOneText(JSON.stringify(sSignerPublicData)));
    return shared;
  }

  // ------------------------------------------------------------------------------

  static getBlinded(
    vals    : GENERATED.DataValue[],
    blinded : number[]
  ) : GENERATED.CredAttrIndexAndDataValue[] {
    return blinded.map((i) => TestData.mkPair(i, vals[i]))
  };

  static getNonBlinded(
    vals    : GENERATED.DataValue[],
    blinded : number[]
  ) : GENERATED.CredAttrIndexAndDataValue[] {
    const excludedIndices = new Set(blinded);
    return vals
      .map((v, i) => TestData.mkPair(i, v))
      .filter((p) => !excludedIndices.has(p.index))
  }

  static mkPair(
    index: number, value: GENERATED.DataValue
  ) : GENERATED.CredAttrIndexAndDataValue {
    return { index: index, value: value };
  }

}
