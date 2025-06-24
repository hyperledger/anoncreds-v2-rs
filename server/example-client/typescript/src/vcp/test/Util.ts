// ------------------------------------------------------------------------------
import * as X from './X';
// ------------------------------------------------------------------------------
import * as GENERATED from 'VCP';
// ------------------------------------------------------------------------------

export class Util {

  // ------------------------------------------------------------------------------

  public static quote(x : string) : string {
    return "\"" + x +  "\"";
  }

  // ------------------------------------------------------------------------------

  public static banner(x : X.X, m : string) {
    this.bannerAux(m + " " + this.zpkLibAndSigTypeString(x));
  }

  public static zpkLibAndSigTypeString(x : X.X) : string {
    return  x.zkpLib + " " + x.sigType.toString();
  }

  public static bannerAux(m : string) {
    console.log('');
    console.log("------------------------- " + m + " -------------------------");
  }

  static readonly DO_PRINT : boolean = false;

  public static sop(m : string, o : any) {
    if (Util.DO_PRINT) {
      this.bannerAux(m);
      console.log(o);
    }
  }

  // ---------------------------------------------------------------------------

  public static mkSPVOneText(x : string) : GENERATED.SharedParamValue {
    return {
      contents : this.mkDVText(x),
      tag      : GENERATED.SPVOneTagEnum.SPV_ONE
    };
  }

  public static mkSPVOneInt(x : number) : GENERATED.SharedParamValue {
    return {
      contents : this.mkDVInt(x),
      tag      : GENERATED.SPVOneTagEnum.SPV_ONE
    };
  }

  public static mkDVInt(x : number) : GENERATED.DataValue {
    return {
      contents : x,
      tag      : GENERATED.DVIntTagEnum.DV_INT
    };
  }

  public static mkDVText(x : string) : GENERATED.DataValue {
    return {
      contents : x,
      tag      : GENERATED.DVTextTagEnum.DV_TEXT
    };
  }

}
