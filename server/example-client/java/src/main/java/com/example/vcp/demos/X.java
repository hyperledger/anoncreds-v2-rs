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
    public final DefaultApi                    api;
    public final SignatureAndRelatedData       dSard;
    public final SignatureAndRelatedData       sSard;
    public final Map<String, SharedParamValue> shared;
    public final Map<String, CredentialReqs>   reqs;
    public final CredentialReqs                credD;
    public final CredentialReqs                credS;

    public X(final String z)
        throws ApiException, IOException
    {
        zkpLib        = z;
        api           = apiSetup();

        // Issuer and Verifier
        final var sss = doCreateSharedAndSigs(zkpLib, api);

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

    public static Object [] doCreateSharedAndSigs(final String zkpLib, final DefaultApi api)
        throws ApiException, IOException
    {
        Util.sop("ClaimTypes D", TestData.dCTs(zkpLib));
        Util.sop("ClaimTypes S", TestData.sCTs(zkpLib));

        // Issuer
        final var dSignerData = api.createSignerData(TestData.dCTs(zkpLib), zkpLib, 0);
        final var sSignerData = api.createSignerData(TestData.sCTs(zkpLib), zkpLib, 1);
        Util.sop("dSignerData D", dSignerData);
        Util.sop("sSignerData S", sSignerData);

        Util.sop("dVals", TestData.dVals());
        Util.sop("sVals", TestData.sVals());

        final var dSig        = api.sign(new SignRequest()
                                         .values(TestData.dVals())
                                         .signerData(dSignerData),
                                         zkpLib, 0
                                         );

        final var sSig        = api.sign(new SignRequest()
                                         .values(TestData.sVals())
                                         .signerData(sSignerData),
                                         zkpLib, 0
                                         );
        Util.sop("dSig", dSig);
        Util.sop("sSig", sSig);

        final var dSard       = new SignatureAndRelatedData()
            .signature(dSig)
            .values(TestData.dVals());
        final var sSard       = new SignatureAndRelatedData()
            .signature(sSig)
            .values(TestData.sVals());

        // Verifier
        final var shared      = TestData.shared(dSignerData.getSignerPublicData().toJson(),
                                                sSignerData.getSignerPublicData().toJson());

        Util.sop("shared", shared);

        final Object [] r     = { dSard, sSard, shared };
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
