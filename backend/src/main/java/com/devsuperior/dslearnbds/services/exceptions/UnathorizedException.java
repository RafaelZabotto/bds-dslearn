package com.devsuperior.dslearnbds.services.exceptions;

public class UnathorizedException extends RuntimeException{
    private static final long serialVersionUID = 1L;

    public UnathorizedException(String msg) {
        super(msg);
    }
}
