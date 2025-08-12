// ------------------------------------------------------------------------------
import {describeError, IndexSignature3Level, isErrorA} from './util';
// ------------------------------------------------------------------------------
import * as GENERATED from 'VCP';
import {ResponseError} from 'VCP';
// ------------------------------------------------------------------------------
import * as undici from 'undici';
// ------------------------------------------------------------------------------

export const AC2C_BBS : string   = "AC2C_BBS";
export const AC2C_PS  : string   = "AC2C_PS";
export const DNC      : string   = "DNC";

export type Accumulator          = string;
export type AccumulatorElement   = string;
export type BlindInfoForSigner   = string;
export type BlindSignature       = string;
export type HolderID             = string;
export type InfoForUnblinding    = string;
export type RangeProofProvingKey = string;
export type MembershipProvingKey = string;
export type Signature            = string;

export type ApiErrorMessage = {
  reason   : string,
  location : string
};

export class ApiError extends Error {
  public apiErrorMessage: ApiErrorMessage;
  public description: string;

  constructor(message: string, descr: string, m: ApiErrorMessage) {
    super(message);
    this.name = "ApiError";
    this.description = descr;
    this.apiErrorMessage = m;
    Object.setPrototypeOf(this, ApiError.prototype);
  }

  // public logError() {
  //   console.error(`${this.name} (${this.statusCode}): ${this.message}`);
  // }
}

export interface VCP {
  network: GENERATED.DefaultApi;

  createSignerData: (
    rngSeed : number,
    cts     : GENERATED.ClaimType[],
    bcs     : number[]
  ) => Promise<GENERATED.SignerData>;

  sign: (
    rngSeed : number,
    sd      : GENERATED.SignerData,
    vs      : GENERATED.DataValue[]
  ) => Promise<Signature>;

  createBlindSigningInfo: (
    rngSeed : number,
    spd     : GENERATED.SignerPublicData,
    blinded : GENERATED.CredAttrIndexAndDataValue[],
  ) => Promise<GENERATED.BlindSigningInfo>,

  signWithBlindedAttributes: (
    rngSeed    : number,
    sd         : GENERATED.SignerData,
    nonblinded : GENERATED.CredAttrIndexAndDataValue[],
    blindInfo  : BlindInfoForSigner,
  ) => Promise<BlindSignature>,

  unblindBlindedSignature: (
    cts               : GENERATED.ClaimType[],
    blinded           : GENERATED.CredAttrIndexAndDataValue[],
    infoForUnblinding : InfoForUnblinding,
    blindSig          : BlindSignature,
  ) => Promise<Signature>,

  createProof: (
    proofReqs : Map<string, GENERATED.CredentialReqs>,
    shared    : Map<string, GENERATED.SharedParamValue>,
    sard      : Map<string, GENERATED.SignatureAndRelatedData>,
    nonce     : string
  ) => Promise<GENERATED.WarningsAndDataForVerifier>,

  verifyProof: (
    proofReqs : Map<string, GENERATED.CredentialReqs>,
    shared    : Map<string, GENERATED.SharedParamValue>,
    dfv       : GENERATED.DataForVerifier,
    drs       : IndexSignature3Level<GENERATED.DecryptRequest>,
    nonce     : string
  ) => Promise<GENERATED.WarningsAndDecryptResponses>,

  verifyDecryption: (
    proofReqs          : Map<string, GENERATED.CredentialReqs>,
    shared             : Map<string, GENERATED.SharedParamValue>,
    proof              : string,
    authDecryptionKeys : Map<string, string>,
    drsp               : IndexSignature3Level<GENERATED.DecryptResponse>,
    nonce              : string
  ) => Promise<GENERATED.Warning[]>

  createRangeProofProvingKey: (
    rngSeed : number
  ) => Promise<RangeProofProvingKey>,

  createAuthorityData: (
    rngSeed : number
  ) => Promise<GENERATED.AuthorityData>,

  createMembershipProvingKey: (
    rngSeed : number
  ) => Promise<MembershipProvingKey>,

  createAccumulatorData: (
    rngSeed : number
  ) => Promise<GENERATED.CreateAccumulatorResponse>,

  createAccumulatorElement: (
    x : string
  ) => Promise<AccumulatorElement>,

  accumulatorAddRemove: (
    ad   : GENERATED.AccumulatorData,
    acc  : Accumulator,
    adds : { [key: HolderID]: AccumulatorElement },
    rms  : AccumulatorElement[],
  ) => Promise<GENERATED.AccumulatorAddRemoveResponse>,

  getAccumulatorWitness: (
    ad   : GENERATED.AccumulatorData,
    acc  : Accumulator,
    elm  : AccumulatorElement,
  ) => Promise<AccumulatorElement>,

}

export function defineCryptoInterfaceWith(zkpLib: string, port: string) : VCP {
  const dispatcher = new undici.Agent({
    headersTimeout : 600000, // 10 minutes
    bodyTimeout    : 600000
  });
  undici.setGlobalDispatcher(dispatcher);

  const network =
    new GENERATED.DefaultApi(new GENERATED.Configuration({basePath: "http://127.0.0.1:" + port}));

  return {
    network,

    createSignerData: async (rng, cts, bcs) => {
      try {
        //console.log("enter createSignerData");
        const x = await network.createSignerData(
          { createSignerDataRequest :
            { claimTypes              : cts,
              blindedAttributeIndices : bcs },
            zkpLib  : zkpLib,
            rngSeed : rng
          });
        //console.log("exit createSignerData");
        return x;
      } catch (error) {
        const e = await handleError(zkpLib, "createSignerData", error)
        throw e;
      }
    },

    sign: async (rng, sd, vs) => {
      try {
        //console.log("enter sign");
        const x = await network.sign(
          { signRequest :
            { values     : vs,
              signerData : sd },
            zkpLib  : zkpLib,
            rngSeed : rng
          });
        //console.log("exit sign");
        return x;
      } catch (error) {
        const e = await handleError(zkpLib, "sign", error)
        throw e;
      }
    },

    createBlindSigningInfo: async (rngSeed, spd, blinded) => {
      try {
        //console.log("enter createBlindeSigningInfo");
        const x = await network.createBlindSigningInfo(
          { createBlindSigningInfoRequest : {
              signerPublicData        : spd,
              blindedIndicesAndValues : blinded },
            rngSeed : rngSeed,
            zkpLib  : zkpLib
          });
        //console.log("exit createBlindeSigningInfo");
        return x;
      } catch (error) {
        const e = await handleError(zkpLib, "createBlindeSigningInfo", error)
        throw e;
      }
    },

    signWithBlindedAttributes: async (rngSeed, sd, nonblinded, blindSigningInfo) => {
      try {
        //console.log("enter signWithBlindedAttributes");
        const x = await network.signWithBlindedAttributes(
          { signWithBlindedAttributesRequest : {
              signerData           : sd,
              blindInfoForSigner   : blindSigningInfo,
              nonBlindedAttributes : nonblinded },
            rngSeed : rngSeed,
            zkpLib  : zkpLib
          });
        //console.log("exit signWithBlindedAttributes");
        return x;
      } catch (error) {
        const e = await handleError(zkpLib, "signWithBlindedAttributes", error)
        throw e;
      }
    },

    unblindBlindedSignature: async (cts, blinded, unblindInfo, blindSig) => {
      try {
        //console.log("enter unblindBlindedSignature");
        const x = await network.unblindBlindedSignature(
          { unblindBlindedSignatureRequest : {
              claimTypes              : cts,
              blindedIndicesAndValues : blinded,
              infoForUnblinding       : unblindInfo,
              blindSignature: blindSig },
            zkpLib  : zkpLib
          });
        //console.log("exit unblindBlindedSignature");
        return x;
      } catch (error) {
        const e = await handleError(zkpLib, "unblindBlinedSignature", error)
        throw e;
      }
    },



    createProof: async (reqs, shared, sard, nonce) => {
      try {
        //console.log("enter createProof");
        const x = await network.createProof(
          { createProofRequest : {
              proofReqs          : Object.fromEntries(reqs)   as { [key: string]: GENERATED.CredentialReqs },
              sharedParams       : Object.fromEntries(shared) as { [key: string]: GENERATED.SharedParamValue },
              sigsAndRelatedData : Object.fromEntries(sard)   as { [key: string]: GENERATED.SignatureAndRelatedData },
              nonce              : nonce },
            zkpLib : zkpLib
          });
        //console.log("exit createProof");
        return x;
      } catch (error) {
        const e = await handleError(zkpLib, "createProof", error)
        throw e;
      }
    },

    verifyProof: async (reqs, shared, dfv, drs, nonce) => {
      try {
        //console.log("enter verifyProof");
        const x = await network.verifyProof(
          { verifyProofRequest : {
              proofReqs       : Object.fromEntries(reqs)   as { [key: string]: GENERATED.CredentialReqs },
              sharedParams    : Object.fromEntries(shared) as { [key: string]: GENERATED.SharedParamValue },
              dataForVerifier : dfv,
              decryptRequests : drs, //mapToObject(drs),
              nonce           : nonce },
            zkpLib : zkpLib
          });
        //console.log("exit verifyProof");
        return x;
      } catch (error) {
        const e = await handleError(zkpLib, "verifyProof", error)
        throw e;
      }
    },

    verifyDecryption: async (reqs, shared, proof, authDecryptionKeys, drsp, nonce) => {
      try {
        //console.log("enter verifyDecryption");
        const response = await network.verifyDecryption(
          { verifyDecryptionRequest : {
              proofReqs        : Object.fromEntries(reqs)               as { [key: string]: GENERATED.CredentialReqs },
              sharedParams     : Object.fromEntries(shared)             as { [key: string]: GENERATED.SharedParamValue },
              proof            : proof,
              decryptionKeys   : Object.fromEntries(authDecryptionKeys) as { [key: string]: string },
              decryptResponses : drsp,
              nonce : nonce },
            zkpLib : zkpLib
        });
        //console.log("exit verifyDecryption");
        return response;
      } catch (error) {
        const e = await handleError(zkpLib, "verifyDecryption", error)
        throw e;
      }
    },

    createRangeProofProvingKey: async (rngSeed) => {
      try {
        //console.log("enter createRangeProofProvingKey");
        const x = await network.createRangeProofProvingKey({ zkpLib: zkpLib, rngSeed: rngSeed });
        //console.log("exit createRangeProofProvingKey");
        return x;
      } catch (error) {
        const e = await handleError(zkpLib, "createRangeProofProvingKey", error)
        throw e;
      }
    },

    createAuthorityData: async (rngSeed) => {
      try {
        //console.log("enter createAuthorityData");
        const x = await network.createAuthorityData({ zkpLib: zkpLib, rngSeed: rngSeed });
        //console.log("exit createAuthorityData");
        return x;
      } catch (error) {
        const e = await handleError(zkpLib, "createAuthorityData", error)
        throw e;
      }
    },

    createMembershipProvingKey: async (rngSeed) => {
      try {
        //console.log("enter createMembershipProvingKey");
        const x = await network.createMembershipProvingKey({ zkpLib: zkpLib, rngSeed: rngSeed });
        //console.log("exit createMembershipProvingKey");
        return x;
      } catch (error) {
        const e = await handleError(zkpLib, "createMembershipProvingKey", error)
        throw e;
      }
    },

    createAccumulatorData: async (rngSeed) => {
      try {
        //console.log("enter createAccumulatorData");
        const x = await network.createAccumulatorData({ zkpLib: zkpLib, rngSeed: rngSeed });
        //console.log("exit createAccumulatorData");
        return x;
      } catch (error) {
        const e = await handleError(zkpLib, "createAccumulatorData", error)
        throw e;
      }
    },

    createAccumulatorElement: async (i) => {
      try {
        //console.log("enter createAccumulatorElement");
        const x = await network.createAccumulatorElement({ zkpLib: zkpLib, body: i });
        //console.log("exit createAccumulatorElement");
        return x;
      } catch (error) {
        const e = await handleError(zkpLib, "createAccumulatorElement", error)
        throw e;
      }
    },

    accumulatorAddRemove: async(ad, acc, adds, rms) => {
      try {
        //console.log("enter accumulatorAddRemove");
        const x = await network.accumulatorAddRemove(
          { accumulatorAddRemoveRequest : {
              accumulatorData: ad,
              accumulator: acc,
              additions: adds,
              removals: rms },
            zkpLib: zkpLib
          });
        //console.log("exit accumulatorAddRemove");
        return x;
      } catch (error) {
        const e = await handleError(zkpLib, "accumulatorAddRemove", error)
        throw e;
      }
    },

    getAccumulatorWitness: async(ad, acc, elm) => {
      try {
        //console.log("enter getAccumulatorElement");
        const x = await network.getAccumulatorWitness(
          { getAccumulatorWitnessRequest : {
              accumulatorData    : ad,
              accumulator        : acc,
              accumulatorElement : elm },
            zkpLib: zkpLib
          });
        //console.log("exit getAccumulatorWitness");
        return x;
      } catch (error) {
        const e = await handleError(zkpLib, "getAccumulatorWitness", error)
        throw e;
      }
    },
  }
}

async function handleError(zkpLib: string, location: string, error : any) : Promise<ApiError> {
  const errStr = describeError(error);
  if (isErrorA<ResponseError>("ResponseError", error)) {
    const message = await error.response.json();
    const messageAsApiErrorMessage = message as ApiErrorMessage;
    throw new ApiError("zkpLib is: " + zkpLib, errStr, messageAsApiErrorMessage);
  } else if (isErrorA("FetchError", error)) {
    throw new ApiError("zkpLib is: " + zkpLib, errStr, { reason: "FetchError", location: location });
  } else {
    throw new ApiError("zkpLib is: " + zkpLib, errStr, { reason: "UNKNOWN", location: location });
  }
}

