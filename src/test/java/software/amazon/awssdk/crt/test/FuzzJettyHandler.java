package software.amazon.awssdk.crt.test;

import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.junit.Ignore;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

@Ignore
final class FuzzJettyHandler extends AbstractHandler {

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
