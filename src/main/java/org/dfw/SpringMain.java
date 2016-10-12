package org.dfw;

import okhttp3.Call;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;

//[Android Https 相关完全解析 当OkHttp遇到Https](http://android.jobbole.com/81613/)
//[将安全证书导入到java的cacerts证书库](http://www.mamicode.com/info-detail-99920.html)

@SpringBootApplication
public class SpringMain {


    public static void main(String[] args) throws Exception {
        ApplicationContext applicationContext = SpringApplication.run(SpringMain.class, args);
        HttpIo httpIo = applicationContext.getBean(HttpIo.class);
        for (String url : new String[]{"https://www.jd.com", "https://www.baidu.com", "https://www.amazon.cn/"}) {
            Call call = httpIo.get(url, null);
            System.out.println(call.execute().body().string());
        }
    }
}
