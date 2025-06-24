package com.example.vcp.demos;

// ---------------------------------------------------------------------------
import com.example.vcp.client.api.DefaultApi;
import com.example.vcp.client.ApiException;
import com.example.vcp.client.Configuration;
import com.example.vcp.client.model.*;
// ---------------------------------------------------------------------------
import java.io.IOException;
import java.util.*;
// ---------------------------------------------------------------------------

@SuppressWarnings("unchecked")
public class X {
    static final String                        port = "8080";
    public final String                        zkpLib;
    public final SigType                       sigType;
    public final DefaultApi                    api;
    public final SignatureAndRelatedData       dSard;
    public final SignatureAndRelatedData       sSard;
    public final Map<String, SharedParamValue> shared;
    public final Map<String, CredentialReqs>   reqs;
    public final CredentialReqs                credD;
    public final CredentialReqs                credS;

    public enum SigType { Blinded, NonBlinded }

    public X(final String z, final SigType st)
        throws ApiException, IOException
    {
        zkpLib        = z;
        sigType       = st;
        api           = apiSetup();

        // Issuer and Verifier
        final var sss = doCreateSharedAndSigs(zkpLib, sigType, api);

        // Verifier
        shared        = (Map<String, SharedParamValue>) sss[2];
        reqs          = TestData.proofReqs();

        // Holder
        dSard         = (SignatureAndRelatedData) sss[0];
        sSard         = (SignatureAndRelatedData) sss[1];
        credD         = reqs.get(TestData.DL);
        credS         = reqs.get(TestData.SUB);
    }

    public static DefaultApi apiSetup() {
        final var client = Configuration.getDefaultApiClient();
        client.setBasePath("http://localhost:" + port);
        // DNC keys can be big, and verifiable encryption can take a long time.
        // Don't close the connection.
        client.setConnectTimeout(0);
        client.setReadTimeout(0);
        client.setWriteTimeout(0);
        return new DefaultApi(client);
    }

    public static Object [] doCreateSharedAndSigs(final String zkpLib, final SigType sigType, final DefaultApi api)
        throws ApiException, IOException
    {
        Util.sop("ClaimTypes D", TestData.dCTs(zkpLib));
        Util.sop("ClaimTypes S", TestData.sCTs(zkpLib));

        // Issuer
        final var sDataAndSigs= createSignerDataAndSignatures(zkpLib, sigType, api);
        final var dSignerData = (SignerData) sDataAndSigs[0];
        final var sSignerData = (SignerData) sDataAndSigs[1];

        Util.sop("dSignerData D", dSignerData);
        Util.sop("sSignerData S", sSignerData);

        Util.sop("dVals", TestData.dVals());
        Util.sop("sVals", TestData.sVals());

        final var dSig        = (String) sDataAndSigs[2];
        final var sSig        = (String) sDataAndSigs[3];

        Util.sop("dSig", dSig);
        Util.sop("sSig", sSig);

        final var dSard       = new SignatureAndRelatedData()
            .signature(dSig)
            .values(TestData.dVals());
        final var sSard       = new SignatureAndRelatedData()
            .signature(sSig)
            .values(TestData.sVals());

        // Verifier
        final var shared      = TestData.shared(dSignerData.getSignerPublicData(),
                                                sSignerData.getSignerPublicData());

        Util.sop("shared", shared);

        final Object [] r     = { dSard, sSard, shared };
        return r;
    }

    public static Object [] createSignerDataAndSignatures(
      final String zkpLib, final SigType sigType, final DefaultApi api)
        throws ApiException, IOException
    {
        final SignerData dSignerData;
        final SignerData sSignerData;
        final String dSig;
        final String sSig;
        if (sigType == X.SigType.NonBlinded) {
            dSignerData = api.createSignerData(new CreateSignerDataRequest()
                                               .claimTypes(TestData.dCTs(zkpLib))
                                               .blindedAttributeIndices(new ArrayList<Integer>()),
                                               zkpLib, 0);
            sSignerData = api.createSignerData(new CreateSignerDataRequest()
                                               .claimTypes(TestData.sCTs(zkpLib))
                                               .blindedAttributeIndices(new ArrayList<Integer>()),
                                               zkpLib, 1);
            dSig = api.sign(new SignRequest()
                            .values(TestData.dVals())
                            .signerData(dSignerData),
                            zkpLib, 0);
            sSig = api.sign(new SignRequest()
                            .values(TestData.sVals())
                            .signerData(sSignerData),
                            zkpLib, 0);
        } else {
            dSignerData = api.createSignerData(new CreateSignerDataRequest()
                                               .claimTypes(TestData.dCTs(zkpLib))
                                               .blindedAttributeIndices(TestData.DL_BLINDED_INDICES),
                                               zkpLib, 0);
            sSignerData = api.createSignerData(new CreateSignerDataRequest()
                                               .claimTypes(TestData.sCTs(zkpLib))
                                               .blindedAttributeIndices(TestData.SUB_BLINDED_INDICES),
                                               zkpLib, 1);
            final BlindSigningInfo dBlindSigningInfo =
                api.createBlindSigningInfo(new CreateBlindSigningInfoRequest()
                                           .signerPublicData(dSignerData.getSignerPublicData())
                                           .blindedIndicesAndValues(TestData.dBlindedIndicesAndVals()),
                                           zkpLib, 0);
            final BlindSigningInfo sBlindSigningInfo =
                api.createBlindSigningInfo(new CreateBlindSigningInfoRequest()
                                           .signerPublicData(sSignerData.getSignerPublicData())
                                           .blindedIndicesAndValues(TestData.sBlindedIndicesAndVals()),
                                           zkpLib, 0);
            final String dBlindSignature =
                api.signWithBlindedAttributes(new SignWithBlindedAttributesRequest()
                                              .nonBlindedAttributes(TestData.dNonBlindedIndicesAndVals())
                                              .blindInfoForSigner(dBlindSigningInfo.getBlindInfoForSigner())
                                              .signerData(dSignerData),
                                              zkpLib, 0);
            final String sBlindSignature =
                api.signWithBlindedAttributes(new SignWithBlindedAttributesRequest()
                                              .nonBlindedAttributes(TestData.sNonBlindedIndicesAndVals())
                                              .blindInfoForSigner(sBlindSigningInfo.getBlindInfoForSigner())
                                              .signerData(sSignerData),
                                              zkpLib, 0);
            dSig = api.unblindBlindedSignature(new UnblindBlindedSignatureRequest()
                                               .claimTypes(TestData.dCTs(zkpLib))
                                               .blindedIndicesAndValues(TestData.dBlindedIndicesAndVals())
                                               .blindSignature(dBlindSignature)
                                               .infoForUnblinding(dBlindSigningInfo.getInfoForUnblinding()),
                                               zkpLib, 0); // TODOO-HC: this does not need a RNG seed
            sSig = api.unblindBlindedSignature(new UnblindBlindedSignatureRequest()
                                               .claimTypes(TestData.sCTs(zkpLib))
                                               .blindedIndicesAndValues(TestData.sBlindedIndicesAndVals())
                                               .blindSignature(sBlindSignature)
                                               .infoForUnblinding(sBlindSigningInfo.getInfoForUnblinding()),
                                               zkpLib, 0); // TODOO-HC: this does not need a RNG seed
        }
        final Object [] r = { dSignerData, sSignerData, dSig, sSig };
        return r;
    }

    // Holder
    public static WarningsAndDataForVerifier doCreateProof(final X x)
        throws ApiException, IOException
    {
        final var sigsAndRelatedData = new HashMap<String, SignatureAndRelatedData>();
        sigsAndRelatedData.put(TestData.DL , x.dSard);
        sigsAndRelatedData.put(TestData.SUB, x.sSard);

        return x.api.createProof(x.zkpLib, new CreateProofRequest()
            .proofReqs(x.reqs)
            .sharedParams(x.shared)
            .sigsAndRelatedData(sigsAndRelatedData)
            .nonce(TestData.NONCE));
    }

    // Verifier
    public static WarningsAndDecryptResponses doVerifyProof(
      final X x,
      final DataForVerifier dfv,
      final Map<String, Map<String, Map<String, DecryptRequest>>> decryptRequests)
        throws ApiException, IOException
    {
        return x.api.verifyProof(x.zkpLib, new VerifyProofRequest()
            .proofReqs(x.reqs)
            .sharedParams(x.shared)
            .dataForVerifier(dfv)
            .decryptRequests(decryptRequests)
            .nonce(TestData.NONCE));
    }

}
