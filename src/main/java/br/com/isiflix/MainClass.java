package br.com.isiflix;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class MainClass {
    public static void main(String[] args) {
        String senhaOriginal = "12345";
        String senhaCrypto;

        senhaCrypto = BCrypt.hashpw(senhaOriginal, BCrypt.gensalt());

        System.out.println("Senha original: " + senhaCrypto);

        if (BCrypt.checkpw(senhaOriginal, senhaCrypto)) {
            System.out.println("Acesso permitido");
        } else {
            System.out.println("Acesso negado");
        }

        BCryptPasswordEncoder encoder;
        encoder = new BCryptPasswordEncoder();

        senhaCrypto = encoder.encode(senhaOriginal);

        System.out.println(senhaCrypto);

        if (encoder.matches(senhaOriginal, senhaCrypto)) {
            System.out.println("Acesso permitido");
        } else {
            System.out.println("Acesso negado");
        }

    }
}