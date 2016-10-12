package org.dfw;

import okhttp3.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class HttpIo {
    static final String VERI_SIGN_CERT = "-----BEGIN CERTIFICATE-----\n" +
            "MIIE0zCCA7ugAwIBAgIQGNrRniZ96LtKIVjNzGs7SjANBgkqhkiG9w0BAQUFADCByjELMAkGA1UE\n" +
            "BhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZWZXJpU2lnbiBUcnVzdCBO\n" +
            "ZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJpU2lnbiwgSW5jLiAtIEZvciBhdXRob3JpemVk\n" +
            "IHVzZSBvbmx5MUUwQwYDVQQDEzxWZXJpU2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRp\n" +
            "ZmljYXRpb24gQXV0aG9yaXR5IC0gRzUwHhcNMDYxMTA4MDAwMDAwWhcNMzYwNzE2MjM1OTU5WjCB\n" +
            "yjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZWZXJpU2ln\n" +
            "biBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJpU2lnbiwgSW5jLiAtIEZvciBh\n" +
            "dXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxWZXJpU2lnbiBDbGFzcyAzIFB1YmxpYyBQcmlt\n" +
            "YXJ5IENlcnRpZmljYXRpb24gQXV0aG9yaXR5IC0gRzUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\n" +
            "ggEKAoIBAQCvJAgIKXo1nmAMqudLO07cfLw8RRy7K+D+KQL5VwijZIUVJ/XxrcgxiV0i6CqqpkKz\n" +
            "j/i5Vbext0uz/o9+B1fs70PbZmIVYc9gDaTY3vjgw2IIPVQT60nKWVSFJuUrjxuf6/WhkcIzSdhD\n" +
            "Y2pSS9KP6HBRTdGJaXvHcPaz3BJ023tdS1bTlr8Vd6Gw9KIl8q8ckmcY5fQGBO+QueQA5N06tRn/\n" +
            "Arr0PO7gi+s3i+z016zy9vA9r911kTMZHRxAy3QkGSGT2RT+rCpSx4/VBEnkjWNHiDxpg8v+R70r\n" +
            "fk/Fla4OndTRQ8Bnc+MUCH7lP59zuDMKz10/NIeWiu5T6CUVAgMBAAGjgbIwga8wDwYDVR0TAQH/\n" +
            "BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwbQYIKwYBBQUHAQwEYTBfoV2gWzBZMFcwVRYJaW1hZ2Uv\n" +
            "Z2lmMCEwHzAHBgUrDgMCGgQUj+XTGoasjY5rw8+AatRIGCx7GS4wJRYjaHR0cDovL2xvZ28udmVy\n" +
            "aXNpZ24uY29tL3ZzbG9nby5naWYwHQYDVR0OBBYEFH/TZafC3ey78DAJ80M5+gKvMzEzMA0GCSqG\n" +
            "SIb3DQEBBQUAA4IBAQCTJEowX2LP2BqYLz3q3JktvXf2pXkiOOzEp6B4Eq1iDkVwZMXnl2YtmAl+\n" +
            "X6/WzChl8gGqCBpH3vn5fJJaCGkgDdk+bW48DW7Y5gaRQBi5+MHt39tBquCWIMnNZBU4gcmU7qKE\n" +
            "KQsTb47bDN0lAtukixlE0kF6BWlKWE9gyn6CagsCqiUXObXbf+eEZSqVir2G3l6BFoMtEMze/aiC\n" +
            "Km0oHw0LxOXnGiYZ4fQRbxC1lfznQgUy286dUV4otp6F01vvpX1FQHKOtw5rDgb7MzVIcbidJ4vE\n" +
            "ZV8NhnacRHr2lVz2XTIIM6RUthg/aFzyQkqFOFSDX9HoLPKsEdao7WNq\n" +
            "-----END CERTIFICATE-----";
    static final String OA_CERT = "-----BEGIN CERTIFICATE-----\n" +
            "MIIFFjCCA/6gAwIBAgIQYEyFdLrACUlaAtxPDzXIpTANBgkqhkiG9w0BAQsFADBEMQswCQYDVQQG\n" +
            "EwJVUzEWMBQGA1UEChMNR2VvVHJ1c3QgSW5jLjEdMBsGA1UEAxMUR2VvVHJ1c3QgU1NMIENBIC0g\n" +
            "RzMwHhcNMTUwOTIzMDAwMDAwWhcNMTgwOTIyMjM1OTU5WjCBozELMAkGA1UEBhMCQ04xEjAQBgNV\n" +
            "BAgTCUd1YW5nRG9uZzESMBAGA1UEBxQJR3VhbmdaaG91MTwwOgYDVQQKFDNHdWFuZ3pob3UgTmV0\n" +
            "ZWFzZSBJbnRlcmFjdGl2ZSBFbnRlcnRhaW5tZW50IENvLixMdGQxEzARBgNVBAsUCkdhbWUgRGVw\n" +
            "dC4xGTAXBgNVBAMUECoub2EubmV0ZWFzZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n" +
            "AoIBAQDJcLte4XvmNYL5G42h4UdjxCRddTzsSWqI6/dBH6Ez9DM8//aakiTX6z4xp0IaBidEr1L8\n" +
            "ireaHQiTj+ilfgQ8jl6cCho5Aq/ScZ2OMuYUd2EdmleNU52Z452OSjkoWecCyLh0cQc3hgb12GHV\n" +
            "UKHah3kT2pEdnZ3c+4dQRx9jHuykd+juBjYs3vp++fqyLgnafrI6USza47yT5DwjdGSkpgtI5fuE\n" +
            "0Add9KCSN9AkSirHNdNIJrYDqvUOgKRxAtLKojsmKcverFrA4YrAlJKDgaGuKMMoWh2blsJvLUUW\n" +
            "Cit4Vjau7mrBYmdp47UzPFgRR7yH/+EtSVfWg2LYgdoZAgMBAAGjggGiMIIBnjAbBgNVHREEFDAS\n" +
            "ghAqLm9hLm5ldGVhc2UuY29tMAkGA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgWgMCsGA1UdHwQkMCIw\n" +
            "IKAeoByGGmh0dHA6Ly9nbi5zeW1jYi5jb20vZ24uY3JsMIGdBgNVHSAEgZUwgZIwgY8GBmeBDAEC\n" +
            "AjCBhDA/BggrBgEFBQcCARYzaHR0cHM6Ly93d3cuZ2VvdHJ1c3QuY29tL3Jlc291cmNlcy9yZXBv\n" +
            "c2l0b3J5L2xlZ2FsMEEGCCsGAQUFBwICMDUMM2h0dHBzOi8vd3d3Lmdlb3RydXN0LmNvbS9yZXNv\n" +
            "dXJjZXMvcmVwb3NpdG9yeS9sZWdhbDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHwYD\n" +
            "VR0jBBgwFoAU0m/3lvSFP3I8MH0j2oV4m6N8WnwwVwYIKwYBBQUHAQEESzBJMB8GCCsGAQUFBzAB\n" +
            "hhNodHRwOi8vZ24uc3ltY2QuY29tMCYGCCsGAQUFBzAChhpodHRwOi8vZ24uc3ltY2IuY29tL2du\n" +
            "LmNydDANBgkqhkiG9w0BAQsFAAOCAQEAmcc2O3ilINO5xxRalbw/69tz0UyI5dD7crrpNXEg1wsr\n" +
            "y3+O72ntSvYRAR4jloQxPPbiPgnn3aEMuVgT5TbXfqcnfrFzrLwVKT+XK8lhFd8X1XpxQO8gPGWT\n" +
            "G60r4+2lndgv6X1eOH2gF9nfGLQeqWGRvzOUkKk55j2OceoJDmmo5TjHAicN/FtJDkdNTTOHpdy2\n" +
            "e2vPrg+mcc2WcaaSIBaPGxL+P1hU0ujiyXrv/9RfI8uAs0TKOkueVfcWHjFE8Zl/cOv/xZaE+mKm\n" +
            "45Bi53M/V39Y6/UIGz94KVdlzFtu05s0KSCBBSD14QFkX1wIKnYYbhsmDm2G1BPX0vR5Qg==\n" +
            "-----END CERTIFICATE-----";
    static String GLOBAL_SIGN_CERT = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkG\n" +
            "A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jv\n" +
            "b3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5MDExMjAw\n" +
            "MDBaFw0yODAxMjgxMjAwMDBaMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i\n" +
            "YWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJHbG9iYWxT\n" +
            "aWduIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDaDuaZ\n" +
            "jc6j40+Kfvvxi4Mla+pIH/EqsLmVEQS98GPR4mdmzxzdzxtIK+6NiY6arymAZavp\n" +
            "xy0Sy6scTHAHoT0KMM0VjU/43dSMUBUc71DuxC73/OlS8pF94G3VNTCOXkNz8kHp\n" +
            "1Wrjsok6Vjk4bwY8iGlbKk3Fp1S4bInMm/k8yuX9ifUSPJJ4ltbcdG6TRGHRjcdG\n" +
            "snUOhugZitVtbNV4FpWi6cgKOOvyJBNPc1STE4U6G7weNLWLBYy5d4ux2x8gkasJ\n" +
            "U26Qzns3dLlwR5EiUWMWea6xrkEmCMgZK9FGqkjWZCrXgzT/LCrBbBlDSgeF59N8\n" +
            "9iFo7+ryUp9/k5DPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8E\n" +
            "BTADAQH/MB0GA1UdDgQWBBRge2YaRQ2XyolQL30EzTSo//z9SzANBgkqhkiG9w0B\n" +
            "AQUFAAOCAQEA1nPnfE920I2/7LqivjTFKDK1fPxsnCwrvQmeU79rXqoRSLblCKOz\n" +
            "yj1hTdNGCbM+w6DjY1Ub8rrvrTnhQ7k4o+YviiY776BQVvnGCv04zcQLcFGUl5gE\n" +
            "38NflNUVyRRBnMRddWQVDf9VMOyGj/8N7yy5Y0b2qvzfvGn9LhJIZJrglfCm7ymP\n" +
            "AbEVtQwdpf5pLGkkeB6zpxxxYu7KyJesF12KwvhHhm4qxFYxldBniYUr+WymXUad\n" +
            "DKqC5JlR3XC321Y9YeRq4VzW9v493kHMB65jUr9TU/Qr6cf9tveCX4XSQRjbgbME\n" +
            "HMUfpIBvFSDJ3gyICh3WZlXi/EjJKSZp4A==\n" +
            "-----END CERTIFICATE-----\n";
    Logger logger = LoggerFactory.getLogger(HttpIo.class);
    OkHttpClient httpClient;

    public HttpIo() {

        SSLSocketFactory sslSocketFactory = null;
        try {
            // KeyStore
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null);

            // CUSTOM CERT
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            // 添加自定义证书
            keyStore.setCertificateEntry(UUID.randomUUID().toString(), certificateFactory.generateCertificate(new ByteArrayInputStream(OA_CERT.getBytes("UTF-8"))));
            keyStore.setCertificateEntry(UUID.randomUUID().toString(), certificateFactory.generateCertificate(new ByteArrayInputStream(VERI_SIGN_CERT.getBytes("UTF-8"))));
            keyStore.setCertificateEntry(UUID.randomUUID().toString(), certificateFactory.generateCertificate(new ByteArrayInputStream(GLOBAL_SIGN_CERT.getBytes("UTF-8"))));

            // 证书管理器Factory
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(keyStore);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagerFactory.getTrustManagers(), new SecureRandom());

            sslSocketFactory = sslContext.getSocketFactory();

        } catch (Exception e) {
            logger.error(HttpIo.class.getName(), e);
        }

        // 构造器
        OkHttpClient.Builder okhttpClientBuilder = new OkHttpClient.Builder();
        okhttpClientBuilder.cookieJar(new CookieJar() {
            Map<String, List<Cookie>> cache = new ConcurrentHashMap<String, List<Cookie>>();

            @Override
            public void saveFromResponse(HttpUrl httpUrl, List<Cookie> list) {
                cache.put(httpUrl.host(), list);
            }

            @Override
            public List<Cookie> loadForRequest(HttpUrl httpUrl) {
                List<Cookie> cookieList = cache.get(httpUrl.host());
                if (cookieList == null) {
                    cookieList = new ArrayList<Cookie>();
                }
                return cookieList;
            }
        });
        if (sslSocketFactory != null) {
            okhttpClientBuilder.sslSocketFactory(sslSocketFactory);
        }
        
        // 创建
        httpClient = okhttpClientBuilder.build();
    }

    /**
     * 发起 GET 请求
     */
    public void get(String url, Map<String, String> headerMap, final Callback<Tuple2<Integer, String>, Exception> callback) {
        Request.Builder builder = new Request.Builder()
                .url(url)
                .get();
        if (headerMap != null) {
            for (String key : headerMap.keySet()) {
                builder.addHeader(key, headerMap.get(key));
            }
        }
        httpClient.newCall(builder.build()).enqueue(new okhttp3.Callback() {

            @Override
            public void onFailure(Call call, IOException e) {
                if (callback != null) {
                    callback.onError(e);
                }
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {

                final int code = response.code();
                final String string = response.body().string();
                if (callback != null) {
                    callback.onSuccess(new Tuple2<Integer, String>(code, string));
                }
            }
        });
    }

    /**
     * 发起 GET 请求
     */
    public Call get(String url, Map<String, String> headerMap) {
        Request.Builder builder = new Request.Builder()
                .url(url)
                .get();
        if (headerMap != null) {
            for (String key : headerMap.keySet()) {
                builder.addHeader(key, headerMap.get(key));
            }
        }
        return httpClient.newCall(builder.build());
    }

    /**
     * 发起 POST
     */
    public void post(String url, Map<String, String> headerMap, RequestBody requestBody, final Callback<Tuple2<Integer, String>, Exception> callback) {
        //如果请求的数据为空，则给定一个空的表单，进行提交
        if (requestBody == null) {
            requestBody = new FormBody.Builder().build();
        }
        //构造请求
        Request.Builder builder = new Request.Builder()
                .url(url)
                .post(requestBody);
        if (headerMap != null) {
            for (String key : headerMap.keySet()) {
                builder.addHeader(key, headerMap.get(key));
            }
        }
        httpClient.newCall(builder.build()).enqueue(new okhttp3.Callback() {

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                final int code = response.code();
                final String string = response.body().string();
                if (callback != null) {
                    callback.onSuccess(new Tuple2<Integer, String>(code, string));
                }
            }

            @Override
            public void onFailure(Call call, IOException e) {
                if (callback != null) {
                    callback.onError(e);
                }
            }
        });
    }

    /**
     * 发起 POST
     */
    public Call post(String url, Map<String, String> headerMap, RequestBody requestBody) {
        //如果请求的数据为空，则给定一个空的表单，进行提交
        if (requestBody == null) {
            requestBody = new FormBody.Builder().build();
        }
        //构造请求
        Request.Builder builder = new Request.Builder()
                .url(url)
                .post(requestBody);
        if (headerMap != null) {
            for (String key : headerMap.keySet()) {
                builder.addHeader(key, headerMap.get(key));
            }
        }
        return httpClient.newCall(builder.build());
    }
}
