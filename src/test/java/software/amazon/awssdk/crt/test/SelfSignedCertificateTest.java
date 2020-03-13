package software.amazon.awssdk.crt.test;

import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.hamcrest.CoreMatchers;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TemporaryFolder;
import software.amazon.awssdk.crt.CRT;
import software.amazon.awssdk.crt.http.HttpClientConnectionManager;
import software.amazon.awssdk.crt.http.HttpClientConnectionManagerOptions;
import software.amazon.awssdk.crt.http.HttpException;
import software.amazon.awssdk.crt.http.HttpHeader;
import software.amazon.awssdk.crt.http.HttpRequest;
import software.amazon.awssdk.crt.http.HttpStream;
import software.amazon.awssdk.crt.http.HttpStreamResponseHandler;
import software.amazon.awssdk.crt.io.ClientBootstrap;
import software.amazon.awssdk.crt.io.EventLoopGroup;
import software.amazon.awssdk.crt.io.HostResolver;
import software.amazon.awssdk.crt.io.SocketOptions;
import software.amazon.awssdk.crt.io.TlsContext;
import software.amazon.awssdk.crt.io.TlsContextOptions;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.net.URI;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

public class SelfSignedCertificateTest {
    private static final EventLoopGroup EVENT_LOOP_GROUP = new EventLoopGroup(Runtime.getRuntime().availableProcessors());
    private static final ClientBootstrap CLIENT_BOOTSTRAP =
            new ClientBootstrap(EVENT_LOOP_GROUP, new HostResolver(EVENT_LOOP_GROUP));

    @ClassRule
    public static TemporaryFolder keystoreFolder = new TemporaryFolder();

    private static Server server;

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void testVerifyPeerNoCA() throws Throwable {
        exception.expect(ExecutionException.class);
        exception.expectCause(CoreMatchers.instanceOf(HttpException.class));
        exception.expectMessage("negotiation failed");

        final TlsContextOptions tlsOpts = TlsContextOptions.createDefaultClient();
        tlsOpts.withCertificateAuthority(TemporaryKeystoreFactory.newSelfSignedCAPem());

        final HttpClientConnectionManagerOptions opts = new HttpClientConnectionManagerOptions()
                .withUri(new URI("https://localhost:8338"))
                .withClientBootstrap(CLIENT_BOOTSTRAP)
                .withSocketOptions(new SocketOptions())
                .withTlsContext(new TlsContext(tlsOpts));

        final HttpClientConnectionManager conManager = HttpClientConnectionManager.create(opts);

        conManager.acquireConnection().thenCompose(con -> {
            final CompletableFuture<byte[]> result = new CompletableFuture<>();

            final HttpRequest request = new HttpRequest("GET",
                    "/fuzz?size=2048",
                    new HttpHeader[] {new HttpHeader("Host", "localhost")},
                    null);

            con.makeRequest(request, new HttpStreamResponseHandler() {

                private final ByteArrayOutputStream baos = new ByteArrayOutputStream();

                @Override
                public void onResponseHeaders(HttpStream stream,
                                              int responseStatusCode,
                                              int blockType,
                                              HttpHeader[] nextHeaders) {
                    if (responseStatusCode != 200) {
                        stream.close();
                        con.close();
                        throw new RuntimeException("non-200: " + responseStatusCode);
                    }
                }

                @Override
                public void onResponseComplete(HttpStream stream, int errorCode) {
                    try {
                        if (stream.getResponseStatusCode() != 200) {
                            result.completeExceptionally(new RuntimeException(String.format("non-200: %d",
                                    stream.getResponseStatusCode())));
                        }
                        if (errorCode != CRT.AWS_CRT_SUCCESS) {
                            result.completeExceptionally(new RuntimeException(String.format("CRT error: %s: %s",
                                    CRT.awsErrorString(errorCode), CRT.awsErrorString(errorCode))));
                        }
                        result.complete(baos.toByteArray());
                    } finally {
                        stream.close();
                        con.close();
                    }
                }

                @Override
                public int onResponseBody(HttpStream stream, byte[] bodyBytesIn) {
                    try {
                        baos.write(bodyBytesIn);
                    } catch (Exception e) {
                        stream.close();
                        con.close();
                        result.completeExceptionally(e);
                    }
                    return bodyBytesIn.length;
                }
            });

            return result;
        }).get();
    }

    @BeforeClass
    public static void beforeClass() throws Exception {
        //Log.initLoggingToFile(Log.LogLevel.Trace, System.getProperty("user.dir") + "/crt.log");

        server = new Server();

        final File keystoreFile = keystoreFolder.newFile(UUID.randomUUID().toString() + ".jks");
        final String password = UUID.randomUUID().toString();
        TemporaryKeystoreFactory.newKeystore(keystoreFile, password);

        SslContextFactory sslContextFactory = new SslContextFactory.Server();
        sslContextFactory.setKeyStorePath(keystoreFile.getAbsolutePath());
        sslContextFactory.setKeyStorePassword(password);
        sslContextFactory.setKeyManagerPassword(password);
        sslContextFactory.setTrustStorePath(keystoreFile.getAbsolutePath());
        sslContextFactory.setTrustStorePassword(password);

        HttpConfiguration httpsConfig = new HttpConfiguration();
        httpsConfig.addCustomizer(new SecureRequestCustomizer());

        ServerConnector sslConnector = new ServerConnector(server,
                new SslConnectionFactory(sslContextFactory, HttpVersion.HTTP_1_1.asString()),
                new HttpConnectionFactory(httpsConfig));
        sslConnector.setPort(8338);
        server.addConnector(sslConnector);

        server.setHandler(new FuzzJettyHandler());
        server.start();
    }

    @AfterClass
    public static void afterClass() throws Exception {
        server.stop();
    }
}
