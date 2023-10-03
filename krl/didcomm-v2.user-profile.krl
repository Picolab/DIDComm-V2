ruleset didcomm-v2.user-profile {
  meta {
    name "User Profile"
    description <<
      Implements the user-profile protocol
      https://didcomm.org/user-profile/1.0/
    >>
    use module io.picolabs.wrangler alias wrangler
    use module io.picolabs.did-o alias dcv2
  }
  global {
    upTags = ["didcomm-v2","user-profile"] // meta:rid.split(".")
    generate_user_profile = function(their_did,thid){
      dido:generateMessage({
        "type": "https://didcomm.org/user-profile/1.0/profile",
        "from": dcv2:didMap(){their_did},
        "to": [their_did],
        "thid": thid,
        "body": {
          "profile": ent:profile,
        }
      })
    }
  }
  rule initializeOnInstallation {
    select when wrangler ruleset_installed where event:attrs{"rids"} >< meta:rid
    pre {
      route0 = dcv2:addRoute("https://didcomm.org/user-profile/1.0/profile",
                 "didcomm_v2_user_profile", "profile_received")
      route2 = dcv2:addRoute("https://didcomm.org/user-profile/1.0/request-profile",
                 "didcomm_v2_user_profile", "request_profile_received")
    }
    wrangler:createChannel(
      upTags,
      {"allow":[{"domain":"didcomm_v2_user_profile","name":"*"}],"deny":[]},
      {"allow":[{"rid":meta:rid,"name":"*"}],"deny":[]}
    )
    fired {
      raise didcomm_v2_user_profile event "factory_reset"
    }
  }
  rule keepChannelsClean {
    select when didcomm_v2_user_profile factory_reset
    foreach wrangler:channels(upTags).reverse().tail() setting(chan)
    wrangler:deleteChannel(chan.get("id"))
  }
  rule initializeProfile {
    select when didcomm_v2_user_profile factory_reset
      where ent:profile.isnull()
    fired {
      ent:profile := {}
    }
  }
  rule setProfileGivenComponents {
    select when didcomm_v2_user_profile profile_changed
    fired {
      ent:profile := {"displayName":event:attrs.get("displayName")}
    }
  }
  rule voluntarilySendProfile {
    select when didcomm_v2_user_profile profile_to_volunteer
      their_did re#(.+)# setting(their_did)
    pre {
      message = generate_user_profile(their_did)
      a = dcv2:send(their_did,message)
    }
  }
  rule sendBackRequestedProfile {
    select when didcomm_v2_user_profile request_profile_received
    pre {
      message = event:attrs{"message"}
      their_did = message.get("from")
      up_message = generate_user_profile(their_did,message{"id"})
      a = dcv2:send(their_did,up_message)
    }
  }
  rule receiveProfile {
    select when didcomm_v2_user_profile profile_received
    pre {
      message = event:attrs{"message"}
    }
    if message{["body","send_back_yours"]} then noop()
    fired {
      raise didcomm_v2_user_profile event "request_profile_received"
        attributes event:attrs
    }
  }
}
