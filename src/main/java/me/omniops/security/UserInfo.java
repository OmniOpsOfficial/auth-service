package me.omniops.security;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;
import java.util.List;
import java.util.Map;

@NoArgsConstructor
@AllArgsConstructor
@ToString
@Setter
@Getter
@JsonIgnoreProperties(ignoreUnknown = true)
public class UserInfo {
    @JsonProperty("sub")
    private String id;
    @JsonProperty("username")
    private  String username;
    @JsonProperty("given_name")
    private String firstName;
    @JsonProperty("family_name")
    private String lastName;
    @JsonProperty("email")
    private  String email;
    @JsonProperty("roles")
    private  List<String> roles;
    @JsonProperty("groups")
    private List<String> groups;
    @JsonProperty("models")
    private List<String> models;
    @JsonProperty("attributes")
    private Map<String, List<String>> attributes;

    //    @JsonProperty("preferred_username") String username;
}