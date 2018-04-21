package com.example.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.security.model.TUser;

public interface TUserRepository extends JpaRepository<TUser, Integer>{

}
