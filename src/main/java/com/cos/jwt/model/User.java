package com.cos.jwt.model;

import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Data
@Entity //DB만들어줌
public class User {


    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY) //mysql을 사용하면 Id가 auto increment가 된다.
    private long id;
    private String username;
    private String password;
    private String roles; //USER, ADMIN

    public List<String> getRoleList(){ //role이 두 개 이상일 경우 이렇게 만들어준다. 다른 방법으로는 role이라는 모델을 하나 더 만들어준다.
        //하지만 효율이 좋지 않다고 생각.
        if(this.roles.length()>0){
            return Arrays.asList(this.roles.split(","));
        }else{
            return new ArrayList<>();
        }
    }

}
