package me.daniel.se.quickstart;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;

import io.helidon.common.LogConfig;
import io.helidon.common.http.Http;
import io.helidon.common.reactive.Single;
import io.helidon.config.Config;
import io.helidon.faulttolerance.Async;
import io.helidon.scheduling.Scheduling;
import io.helidon.webserver.ClientAuthentication;
import io.helidon.webserver.Routing;
import io.helidon.webserver.WebServer;
import io.helidon.webserver.WebServerTls;

import static me.daniel.se.quickstart.OCImTLSManager.Type.SERVER;

/**
 * curl --key key-pair.pem --cert cert-chain.cer --cacert ca.cer -v https://localhost:8443
 */
public final class Main {
    private final Config config;
    private final OCImTLSManager mTLSManager;
    private final ScheduledExecutorService taskExecutor;
    private final ExecutorService asyncExecutor;
    private final Async async;

    public Main() {
        config = Config.create();
        mTLSManager = OCImTLSManager.create(SERVER, config.get("security.mtls-reload"));
        taskExecutor = Executors.newScheduledThreadPool(1);
        asyncExecutor = Executors.newCachedThreadPool();
        async = Async.builder().executor(asyncExecutor).build();
    }

    public static void main(final String[] args) {
        LogConfig.configureRuntime();
        new Main().startServer();
    }

    private void startServer() {
        Single<WebServer> webServer = WebServer.builder()
                .config(config.get("server"))

                .addRouting(Routing.builder()
                                    // Unsecured endpoint triggers mTls update
                                    .get("/", (req, res) -> async.invoke(() -> {
                                                updateServerSslContext(req.webServer());
                                                return "mTls context reloaded!";
                                            })
                                            .onError(res::send)
                                            .forSingle(res::send))
                                    .build())

                .addNamedRouting("secured", Routing.builder()
                        // mTLS secured endpoint returns client's cert CN
                        .get("/", (req, res) -> {
                            String cn = req.headers().first(Http.Header.X_HELIDON_CN).orElse("Unknown CN");
                            res.send("Hello " + cn + "!");
                        })
                        .build())
                .build()
                .start();

        webServer.forSingle(this::onServerStart)
                .exceptionally(t -> {
                    System.err.println("Startup failed: " + t.getMessage());
                    t.printStackTrace(System.err);
                    return null;
                });
    }

    private void onServerStart(WebServer ws) {
        ws.whenShutdown().forSingle(this::onServerShutdown);

        String taskIntervalDescription =
                Scheduling.cronBuilder()
                        .executor(taskExecutor)
                        .expression(config.get("security.mtls-reload.reload-cron").asString().get())
                        .task(inv -> updateServerSslContext(ws))
                        .build()
                        .description();

        System.out.println("WebServer is up!");
        System.out.println("Secured   endpoint: https://localhost:" + ws.port("secured") + "/");
        System.out.println("Unsecured endpoint: http://localhost:" + ws.port() + "/");
        System.out.println("Reload interval for mTls is " + taskIntervalDescription);
    }

    private void updateServerSslContext(WebServer ws) {
        try {
            System.out.print("Reloading mTLS context ... ");
            SSLContext sslContext = mTLSManager.loadSSLContext();

            WebServerTls tls = WebServerTls.builder()
                    .clientAuth(ClientAuthentication.REQUIRE)
                    .sslContext(sslContext)
                    .build();

            ws.updateTls(tls, "secured");

            System.out.println("DONE");
        } catch (Exception t) {
            System.out.println("FAILED");
            t.printStackTrace();
        }
    }

    private void onServerShutdown(WebServer ws) {
        try {
            taskExecutor.shutdownNow();
            asyncExecutor.shutdownNow();
            if (!taskExecutor.awaitTermination(10, TimeUnit.SECONDS)
                    || !asyncExecutor.awaitTermination(10, TimeUnit.SECONDS)) {
                System.out.println("Graceful shutdown of async tasks took too long.");
            }
        } catch (InterruptedException ignored) {
        }
        System.out.println("WEB server is DOWN. Good bye!");
    }
}
