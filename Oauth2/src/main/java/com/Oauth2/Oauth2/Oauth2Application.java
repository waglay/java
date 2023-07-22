package com.Oauth2.Oauth2;

import org.modelmapper.ModelMapper;
import org.slf4j.ILoggerFactory;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.logging.Logger;

@SpringBootApplication
public class Oauth2Application implements CommandLineRunner {

	public static void main(String[] args) {
		SpringApplication.run(Oauth2Application.class, args);
	}


	@Bean
 public ModelMapper modelMapper(){
		return new ModelMapper();
 }
 @Autowired
private PasswordEncoder passwordEncoder;

	@Override
	public void run(String... args) throws Exception {
		String me = passwordEncoder.encode("me");
		System.out.println(me);

	}
}
