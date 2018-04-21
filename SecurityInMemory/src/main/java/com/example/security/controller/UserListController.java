package com.example.security.controller;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import com.example.security.model.TUser;
import com.example.security.repository.TUserRepository;

@Controller
public class UserListController {

	@Autowired
	private TUserRepository tUserRepository;		

	@GetMapping("/users")
	public ModelAndView getAllUsersView() {
		ModelAndView mav = new ModelAndView();
		mav.setViewName("userslist");
		mav.addObject("users", this.tUserRepository.findAll());
		return mav;
	}

	@GetMapping("/insert")
	public ModelAndView createUserView() {
		ModelAndView mav = new ModelAndView();
		mav.setViewName("insert-user");
		mav.addObject("user", new TUser());
		return mav;
	}

	@PostMapping("/insert")
	public ModelAndView createUser(@Valid TUser user, BindingResult result) {
		ModelAndView mav = new ModelAndView();	
		user.setPassword(new BCryptPasswordEncoder().encode(user.getPassword()));
		tUserRepository.save(user);			
		mav.addObject("users", tUserRepository.findAll());
		mav.setViewName("userslist");	    
		return mav;
	}

}
