package com.example.vcp.demos;

// ---------------------------------------------------------------------------
import com.example.vcp.client.ApiException;
import com.example.vcp.client.model.*;
// ---------------------------------------------------------------------------
import java.util.*;
// ---------------------------------------------------------------------------

// SEE
//     src/test/java/com/example/vcp/demos/AppTest.java
// for examples of using the various VCP features.

public class App
{
    public static void main(final String[] args) {
        try {
            for (String s: args) { System.out.println(s); }

            if (Arrays.asList(args).contains(TestData.AC2C_BBS)) {
                doit(new X(TestData.AC2C_BBS, X.SigType.NonBlinded));
            }
            if (Arrays.asList(args).contains(TestData.AC2C_PS)) {
                doit(new X(TestData.AC2C_PS, X.SigType.NonBlinded));
            }
            if (Arrays.asList(args).contains(TestData.DNC)) {
                doit(new X(TestData.DNC, X.SigType.NonBlinded));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void doit(final X x)
    {
        try {
            Util.banner(x, "VCP");
            Util.sop("dSard"     , x.dSard);
            Util.sop("sSard"     , x.sSard);
            Util.sop("shared"    , x.shared);
            Util.sop("proof reqs", x.reqs);

            Util.banner(x, "create");
            final var cprsp = X.doCreateProof(x);
            Util.sop("proof", cprsp);

            Util.banner(x, "verify");
            Map<String, Map<String, Map<String, DecryptRequest>>> decryptRequests = new HashMap<>();
            final var vrsp  = X.doVerifyProof(x, cprsp.getDataForVerifier(), decryptRequests);
            Util.sop("verify", vrsp);
        } catch (ApiException e) {
            System.err.println("Exception");
            System.err.println(e.getCode());
            System.err.println(e.getMessage());
            System.err.println(e.getCause());
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
