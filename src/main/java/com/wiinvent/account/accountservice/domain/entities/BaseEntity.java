package com.wiinvent.account.accountservice.domain.entities;

import lombok.Data;
import org.springframework.data.mongodb.core.mapping.Field;

import java.io.Serializable;

@Data
public abstract class BaseEntity implements Serializable {

    @Field(name = "created_at")
    protected Long createdAt = DateUtils
}
