package software.amazon.awssdk.crt.test;

import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import software.amazon.awssdk.crt.CRT;
import software.amazon.awssdk.crt.http.HttpClientConnection;
import software.amazon.awssdk.crt.http.HttpClientConnectionManager;
import software.amazon.awssdk.crt.http.HttpClientConnectionManagerOptions;
import software.amazon.awssdk.crt.http.HttpHeader;
import software.amazon.awssdk.crt.http.HttpRequest;
import software.amazon.awssdk.crt.http.HttpRequestBodyStream;
import software.amazon.awssdk.crt.http.HttpStream;
import software.amazon.awssdk.crt.http.HttpStreamResponseHandler;
import software.amazon.awssdk.crt.io.ClientBootstrap;
import software.amazon.awssdk.crt.io.EventLoopGroup;
import software.amazon.awssdk.crt.io.HostResolver;
import software.amazon.awssdk.crt.io.SocketOptions;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.DoubleSummaryStatistics;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;
import java.util.stream.Collectors;

import static java.lang.String.format;
import static java.util.concurrent.TimeUnit.NANOSECONDS;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class PerformanceIntegrationTest {

    // Tuneable parameters

    private static final int NUM_REQUESTS = 1_000_000;
    private static final int NUMBER_OF_THREADS_MAKING_REQUESTS = 50;
    private static final int NUMBER_OF_CRT_CONNECTIONS = 64 * 1024;
    private static final int RESPONSE_SIZE = 2048;

    private static Server server;

    @BeforeClass
    public static void beforeClass() throws Exception {
        //Log.initLoggingToFile(Log.LogLevel.Trace, System.getProperty("user.dir") + "/crt.log");

        server = new Server(8337);
        server.setHandler(new FuzzHandler());
        server.start();
    }

    @AfterClass
    public static void afterClass() throws Exception {
        server.stop();
    }

    @Test
    public void benchmark() throws Exception {
        final ExecutorService benchmarkService = createThreadpool();
        final LongAdder failedRequests = new LongAdder();
        final AtomicLong completedRequests = new AtomicLong();
        final DoubleSummaryStatistics latencyStats = new DoubleSummaryStatistics();
        final TestClient client = new TestClient(new URI("http://localhost:8337"), NUMBER_OF_CRT_CONNECTIONS);

        final long startTime = System.nanoTime();
        for (int i = 0; i < NUM_REQUESTS; i++) {
            benchmarkService.submit(() -> {
                final long requestTime = System.nanoTime();
                try {
                    sendFuzzRequest(client);
                } catch (Throwable t) {
                    t.printStackTrace();
                    failedRequests.increment();
                } finally {
                    final long endTime = System.nanoTime();
                    final long requestNum = completedRequests.incrementAndGet();
                    latencyStats.accept(TimeUnit.NANOSECONDS.toMillis(endTime - requestTime));
                    if (requestNum % 5000 == 0 || requestNum > NUM_REQUESTS - 50) {
                        final long elapsed = NANOSECONDS.toMillis(endTime - startTime);
                        System.out.printf("T+%,d ms: %d requests (%,3.2f tps) (last request: %,d ms)%n",
                                elapsed, requestNum, ((double) requestNum) / elapsed * 1000D,
                                NANOSECONDS.toMillis(endTime - requestTime));
                    }
                }
            });
        }

        benchmarkService.shutdown();
        assertTrue(benchmarkService.awaitTermination(1, TimeUnit.HOURS));

        long endTime = System.nanoTime();
        double averageLatency = latencyStats.getAverage();
        System.out.printf("=================================%n");
        System.out.printf("%s%n", getUserAgent());
        System.out.printf("=================================%n");
        System.out.printf("%-20s: %,d%n", "Concurrency level", NUMBER_OF_THREADS_MAKING_REQUESTS);
        System.out.printf("%-20s: %,d secs%n", "Time taken for tests", NANOSECONDS.toSeconds(endTime - startTime));
        System.out.printf("%-20s: %,d%n", "Complete requests", NUM_REQUESTS);
        System.out.printf("%-20s: %,d%n", "Failed requests", failedRequests.sum());
        System.out.printf("%-20s: %,3.2f%n", "Requests per second", (double)NUM_REQUESTS / NANOSECONDS.toSeconds(endTime - startTime));
        System.out.printf("%-20s: %,.2f ms%n", "Avg request latency", averageLatency);

        assertEquals(failedRequests.sum() + " requests failed.", 0, failedRequests.sum());
    }

    private void sendFuzzRequest(TestClient client) throws ExecutionException, InterruptedException {
        final Response response = client.sendRequest("GET",
                Collections.singletonMap("User-Agent", getUserAgent()),
                "/fuzz",
                Collections.singletonMap("size", String.valueOf(RESPONSE_SIZE)),
                null).get();

        Assert.assertEquals(200, response.getStatusCode());
        Assert.assertEquals(RESPONSE_SIZE, response.getBody().length);
    }

    private String getUserAgent() {
        return "Coral/AWS-CRT-java";
    }

    private static ExecutorService createThreadpool() {
        return Executors.newFixedThreadPool(NUMBER_OF_THREADS_MAKING_REQUESTS,
                new ThreadFactory() {
                    private final AtomicInteger num = new AtomicInteger();

                    @Override
                    public Thread newThread(Runnable r) {
                        final Thread t = new Thread(r);
                        t.setName(String.format("benchmark-%d", num.incrementAndGet()));
                        t.setDaemon(true);
                        return t;
                    }
                });
    }

    static final class TestClient {
        private static final EventLoopGroup EVENT_LOOP_GROUP = new EventLoopGroup(Runtime.getRuntime().availableProcessors());
        private static final ClientBootstrap CLIENT_BOOTSTRAP =
                new ClientBootstrap(EVENT_LOOP_GROUP, new HostResolver(EVENT_LOOP_GROUP));

        private final URI endpoint;
        private final HttpClientConnectionManager conManager;

        TestClient(URI endpoint, int maxConns) {
            this.endpoint = endpoint;
            final HttpClientConnectionManagerOptions opts = new HttpClientConnectionManagerOptions()
                    .withUri(endpoint)
                    .withClientBootstrap(CLIENT_BOOTSTRAP)
                    .withSocketOptions(new SocketOptions());

            if (maxConns > 0) {
                opts.withMaxConnections(maxConns);
            }

            conManager = HttpClientConnectionManager.create(opts);
        }

        CompletableFuture<Response> sendRequest(String verb, Map<String, String> headers, String path, Map<String, String> params, byte[] body) {
            final String joinedParams = params.entrySet().stream()
                    .map(e -> {
                        try {
                            return URLEncoder.encode(e.getKey(), "UTF-8") + "=" + URLEncoder.encode(e.getValue(), "UTF-8");
                        } catch (UnsupportedEncodingException ex) {
                            throw new Error("Can't happen", ex);
                        }
                    })
                    .collect(Collectors.joining("&"));

            return conManager.acquireConnection().handle((con, err) -> {
                if (err != null) {
                    if (con != null) {
                        conManager.releaseConnection(con);
                    }
                    throw new RuntimeException(err);
                }

                return con;
            }).thenCompose(con -> {
                final StringBuilder pathBuilder = new StringBuilder(path == null ? "/" : path);
                if (!params.isEmpty()) {
                    pathBuilder.append("?").append(joinedParams);
                }

                final HttpRequest request = new HttpRequest(verb,
                        pathBuilder.toString(),
                        getHeaders(headers, body),
                        new BodyStream(body));

                final CompletableFuture<Response> result = new CompletableFuture<>();

                final HttpStream stream = con.makeRequest(request, new ResponseStreamHandler(con, result));
                try {
                    stream.activate();
                } catch (Exception e) {
                    result.completeExceptionally(e);
                }

                return result;

            });
        }

        private HttpHeader[] getHeaders(Map<String, String> headers, byte[] body) {
            final List<HttpHeader> result = new ArrayList<>(headers.size() + 2);
            for (final Map.Entry<String, String> e : headers.entrySet()) {
                result.add(new HttpHeader(e.getKey(), e.getValue()));
            }
            if (body != null && body.length > 0) {
                result.add(new HttpHeader("Content-length", String.valueOf(body.length)));
            }
            result.add(new HttpHeader("Host", "localhost"));
            return result.toArray(new HttpHeader[0]);
        }

        private static final class BodyStream implements HttpRequestBodyStream {
            final ByteBuffer request;
            public BodyStream(byte[] bytes) {
                request = bytes == null ? ByteBuffer.allocate(0) : ByteBuffer.wrap(bytes);
            }

            @Override
            public boolean sendRequestBody(ByteBuffer bodyBytesOut) {
                ByteBuffer slice = request.slice();
                if (bodyBytesOut.remaining() < slice.remaining()) {
                    slice.limit(bodyBytesOut.remaining());
                }
                bodyBytesOut.put(slice);
                request.position(request.position() + slice.limit());
                return request.remaining() == 0;
            }

            @Override
            public boolean resetPosition() {
                request.position(0);
                return true;
            }
        }

        private static final class ResponseStreamHandler implements HttpStreamResponseHandler {

            private final Response.Builder responseBuilder = new Response.Builder();
            private final HttpClientConnection con;
            private final CompletableFuture<Response> result;

            public ResponseStreamHandler(HttpClientConnection con, CompletableFuture<Response> result) {
                this.con = con;
                this.result = result;
            }

            @Override
            public void onResponseHeaders(HttpStream stream, int responseStatusCode, int blockType, HttpHeader[] nextHeaders) {
                responseBuilder.withStatusCode(responseStatusCode);
                for (final HttpHeader h : nextHeaders) {
                    responseBuilder.addHeader(h.getName(), h.getValue());
                }
            }

            @Override
            public void onResponseComplete(HttpStream stream, int errorCode) {
                try {
                    if (errorCode != CRT.AWS_CRT_SUCCESS) {
                        final String errorMessage = format("Unknown response error (0x%03x). %s: %s",
                                errorCode, CRT.awsErrorName(errorCode), CRT.awsErrorString(errorCode));
                        result.completeExceptionally(new RuntimeException(errorMessage));
                    } else {
                        if (responseBuilder.statusCode == 0) {
                            responseBuilder.withStatusCode(stream.getResponseStatusCode());
                        }
                        result.complete(responseBuilder.build());
                    }
                } finally {
                    stream.close();
                    con.close();
                }
            }

            @Override
            public int onResponseBody(HttpStream stream, byte[] bodyBytesIn) {
                try {
                    responseBuilder.bodyContent(bodyBytesIn);
                } catch (Throwable t) {
                    result.completeExceptionally(t);
                    stream.close();
                    con.close();
                }
                return bodyBytesIn.length;
            }
        }
    }

    static final class Response {

        private final int statusCode;
        private final Map<String, List<String>> headers;
        private final byte[] body;

        private Response(int statusCode, Map<String, List<String>> headers, byte[] body) {
            this.statusCode = statusCode;
            this.headers = headers;
            this.body = body;
        }

        public int getStatusCode() {
            return statusCode;
        }

        public Map<String, List<String>> getHeaders() {
            return headers;
        }

        public byte[] getBody() {
            return body;
        }

        public static final class Builder {

            private int statusCode;
            private Map<String, List<String>> headers = new HashMap<>();
            private ByteArrayOutputStream bodyStream = new ByteArrayOutputStream();

            public Builder withStatusCode(int statusCode) {
                this.statusCode = statusCode;
                return this;
            }

            public Builder addHeader(String key, String value) {
                headers.computeIfAbsent(key, unused -> new ArrayList<>()).add(value);
                return this;
            }

            public Builder bodyContent(byte[] bytes) throws IOException {
                bodyStream.write(bytes);
                return this;
            }

            public Response build() {
                return new Response(statusCode, Collections.unmodifiableMap(headers), bodyStream.toByteArray());
            }
        }
    }

    static final class FuzzHandler extends AbstractHandler {

        @Override
        public void handle(String target,
                           Request request,
                           HttpServletRequest httpServletRequest,
                           HttpServletResponse httpServletResponse) throws IOException, ServletException {
            final Map<String, String[]> params = request.getParameterMap();
            int size;
            if (params.containsKey("size")) {
                size = Integer.parseInt(params.get("size")[0]);
            } else {
                size = ThreadLocalRandom.current().nextInt(8192);
            }
            int code;
            if (params.containsKey("code")) {
                code = Integer.parseInt(params.get("code")[0]);
            } else {
                code = 200;
            }

            byte[] response = new byte[size];
            ThreadLocalRandom.current().nextBytes(response);

            httpServletResponse.setContentType("application/octet-stream");
            httpServletResponse.setContentLength(response.length);
            httpServletResponse.setStatus(code);
            httpServletResponse.getOutputStream().write(response);
            httpServletResponse.getOutputStream().flush();

            request.setHandled(true);
        }
    }
}
