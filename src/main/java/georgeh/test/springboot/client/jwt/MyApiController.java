package georgeh.test.springboot.client.jwt;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MyApiController {

    @GetMapping("/hello")
    public String hello() {
        return "Hello";
    }

}
