ruleset oob {
  meta {
    use module io.picolabs.wrangler alias wrangler
    use module io.picolabs.did-o alias dcv2
    provides generate_invitation
    shares generate_invitation, invite
  }
  global {
    generate_invitation = function(label){
      eci = wrangler:channels(["oob","ui"]).head().get("id")
      parts = dcv2:generate_invitation(label).split("/invite?")
      <<#{meta:host}/c/#{eci}/query/#{meta:rid}/invite.html?#{parts[1]}>>
    }
    invite = function(_oob){
      json = _oob.math:base64decode().decode()
      type = json.get("type").split("/").reverse().head()
      createdZ = time:new(json.get("created_time")*1000)
      createdM = time:add(createdZ,{"hours": -6})
      created = createdM.replace(re#.000Z$#," MDT").replace("T"," ")
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
$(function(){
  to_show = "http://www.example.com/invite"+location.search;
  $("div").qrcode({ text: to_show, foreground: "#000000" });
});
</script>
<style type="text/css">
h1, h2, p, dt, dd {
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
<dt>label</dt><dd>#{json.get(["body","label"])}</dd>
<dt>created</dt><dd>#{created}</dd>
</dl>
<h2>Call to action</h2>
<p>To respond with a DIDComm v2 agent, copy/paste this URI:</p>
<textarea>http://www.example.com/invite?_oob=#{_oob}</textarea>
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
  </body>
</html>
>>
    }
  }
  rule initialize {
    select when wrangler ruleset_installed where event:attr("rids") >< meta:rid
    every {
      wrangler:createChannel(
        ["oob","ui"],
        {"allow":[],"deny":[{"domain":"*","name":"*"}]},
        {"allow":[{"rid":meta:rid,"name":"*"}],"deny":[]}
      )
    }
    fired {
      raise oob event "factory_reset"
    }
  }
  rule keepChannelsClean {
    select when oob factory_reset
    foreach wrangler:channels(["oob","ui"]).reverse().tail() setting(chan)
    wrangler:deleteChannel(chan.get("id"))
  }
}

