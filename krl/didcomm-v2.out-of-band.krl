ruleset didcomm-v2.out-of-band {
  meta {
    use module io.picolabs.wrangler alias wrangler
    use module io.picolabs.did-o alias dcv2
    provides generate_invitation, connections
    shares generate_invitation, invite, raw_shortcuts
  }
  global {
    connections = function(){
      ent:connections
    }
    raw_shortcuts = function(){
      ent:shortcuts
    }
    shortcut_url = function(){
      ed = "didcomm_v2_out_of_band"
      et = "shortcut_need_changed"
      <<#{meta:host}/sky/event/#{meta:eci}/none/#{ed}/#{et}>>
    }
    invite_url = function(args){
      eci = wrangler:channels(["oob","ui"]).head().get("id")
      <<#{meta:host}/c/#{eci}/query/#{meta:rid}/invite.html?#{args.join("&")}>>
    }
    generate_invitation = function(label){
      parts = dcv2:generate_invitation(label).split("/invite?")
      invite_url(parts.tail()) // ["_oob=eyJ..."]
    }
    invite = function(_oob,orig){
      json = _oob.math:base64decode().decode()
      type = json.get("type").split("/").reverse().head()
      createdZ = time:new(json.get("created_time")*1000)
      createdM = time:add(createdZ,{"hours": -6})
      created = createdM.replace(re#.000Z$#," MDT").replace("T"," ")
      radio_js = << onchange="this.form.submit()">>
      is_regular = orig.isnull() || orig.length() == 0
      is_short = not is_regular
      label = json.get(["body","label"])
      the_invite = function(){
        is_regular => "http://www.example.com/invite?_oob="+_oob |
        is_short   => orig |
                      "cannot happen"
      }
      <<<!DOCTYPE HTML>
<html>
  <head>
    <title>#{type}</title>
    <meta charset="UTF-8">
<script src="https://manifold.picolabs.io:9090/js/jquery-3.1.0.min.js"></script>
<!-- thanks to Jerome Etienne http://jeromeetienne.github.io/jquery-qrcode/ -->
<script type="text/javascript" src="https://manifold.picolabs.io:9090/js/jquery.qrcode.js"></script>
<script type="text/javascript" src="https://manifold.picolabs.io:9090/js/qrcode.js"></script>
<script type="text/javascript">
  function selectAll(e){
    e.preventDefault();
    const range = document.createRange();
    range.selectNodeContents(e.target);
    const sel = window.getSelection();
    if(sel){
      sel.removeAllRanges();
      sel.addRange(range);
    }
  }
</script>
<style type="text/css">
h1, h2, p, dt, dd, form {
  font-family: Arial, sanserif;
}
textarea {
  min-height: 3em;
  min-width: 30em;
}
</style>
  </head>
  <body>
<h1>DIDComm v2 out-of-band message</h1>
<h2>Explanation</h2>
<p>This URI is a DIDComm v2 out-of-band message.</p>
<dl>
<dt>type</dt><dd>#{json.get("type").split("/").reverse().head()}</dd>
<dt>goal</dt><dd>#{json.get(["body","goal"])}</dd>
<dt>label</dt><dd>#{label}</dd>
<dt>created</dt><dd>#{created}</dd>
</dl>
<h2>Call to action</h2>
<form action="#{shortcut_url()}" method="POST">
Message format:
<input type="radio" name="fmt" value="regular"#{is_regular => " checked" | ""}#{radio_js} id="radio_regular">
<label for="radio_regular">regular</label>
<input type="radio" name="fmt" value="short"#{is_short => " checked" | ""}#{radio_js} id="radio_short">
<label for="radio_short">short</label>
<input type="hidden" name="_oob" value="#{_oob}">
<input type="hidden" name="tag" value="#{label}">
</form>
<p>To respond with a DIDComm v2 agent, copy/paste this URI:</p>
<textarea id="the_invite" onclick="selectAll(event)" title="click to select all" readonly>#{the_invite()}</textarea>
<p>To respond with a DIDComm v2 wallet, scan this QR Code:</p>
<div style="border:1px dashed silver;padding:5px;width:max-content"></div>
<h2>Technical details (part one)</h2>
<pre>
<script type="text/javascript">
  document.write(JSON.stringify(#{json.encode()},null,2))
</script>
</pre>
<h2>Technical details (part two)</h2>
<pre>
<script type="text/javascript">
  document.write(JSON.stringify(#{dcv2:didDocs().get(json.get("from")).encode()},null,2))
</script>
</pre>
<script type="text/javascript">
$(function(){
  to_show = $("#the_invite").val();
  $("div").qrcode({ text: to_show, foreground: "#000000" });
});
</script>
  </body>
</html>
>>
    }
  }
  rule initialize {
    select when wrangler ruleset_installed where event:attrs{"rids"} >< meta:rid
    every {
      wrangler:createChannel(
        ["oob","ui"],
        {"allow":[{"domain":"didcomm_v2_out_of_band","name":"*"}],"deny":[]},
        {"allow":[{"rid":meta:rid,"name":"*"}],"deny":[]}
      )
    }
    fired {
      raise didcomm_v2_out_of_band event "factory_reset"
    }
  }
  rule keepChannelsClean {
    select when didcomm_v2_out_of_band factory_reset
    foreach wrangler:channels(["oob","ui"]).reverse().tail() setting(chan)
    wrangler:deleteChannel(chan.get("id"))
  }
  rule initializeShortcutStore {
    select when didcomm_v2_out_of_band factory_reset
      where ent:shortcuts.isnull()
    fired {
      ent:shortcuts := {}
    }
  }
  rule initializeConnectionsStore {
    select when didcomm_v2_out_of_band factory_reset
      where ent:connections.isnull()
    fired {
      ent:connections := {}
    }
  }
  rule generateAndShowInvitation {
    select when didcomm_v2_out_of_band invitation_needed
      label re#(.+)# setting(label)
    pre {
      parts = dcv2:generate_invitation(label).split("/invite?")
      the_invite = invite_url(parts.tail()) // ["_oob=eyJ..."]
      the_connection_so_far = {
        "label": label,
        "_oob": parts.tail().head().split("=").tail().join("=")
      }
    }
    send_directive("_redirect",{"url":the_invite})
    fired {
      ent:connections{label} := the_connection_so_far
    }
  }
  rule createShortcutIfNeeded {
    select when didcomm_v2_out_of_band shortcut_need_changed
      _oob re#(eyJ.+)#
      fmt re#^short$#
      setting(_oob)
    pre {
      tag = event:attrs{"tag"}.lc().replace(re#[^a-z0-9_.-]#g,"-")
      eid = tag => tag | "none"
      shortcut = function(eci){
        <<#{meta:host}/sky/event/#{eci}/#{eid}/s/u>>
      }
      shortcut_already_exists = ent:shortcuts{_oob}.length()
    }
    if not shortcut_already_exists then
      wrangler:createChannel(
        [eid,"s"],
        {"allow":[{"domain":"s","name":"u"}],"deny":[]},
        {"allow":[],"deny":[{"rid":"*","name":"*"}]}
      ) setting(channel)
    fired {
      ent:shortcuts{_oob} := shortcut(channel{"id"})
    }
  }
  rule changeToShortFormat {
    select when didcomm_v2_out_of_band shortcut_need_changed
      _oob re#(eyJ.+)#
      fmt re#^short$#
      setting(_oob)
    pre {
      shortcut = ent:shortcuts{_oob}
      long_orig_short = invite_url(["_oob="+_oob,"orig="+shortcut])
    }
    send_directive("_redirect",{"url":long_orig_short})
  }
  rule revertToLongFormat {
    select when didcomm_v2_out_of_band shortcut_need_changed
      _oob re#(eyJ.+)#
      fmt re#^regular$#
      setting(_oob)
    send_directive("_redirect",{"url":invite_url(["_oob="+_oob])})
  }
  rule redirectFromShortcut {
    select when s u
    pre {
      mre = ("/sky/event/"+meta:eci+"/").as("RegExp")
      _oob = ent:shortcuts
        .filter(function(s,o){s.match(mre)})
        .keys()
        .head()
    }
    send_directive("_redirect",{"url":invite_url(["_oob="+_oob])})
  }
}
