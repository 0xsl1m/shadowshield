"use client";
import { useEffect, useRef, useState } from "react";

// The CSS orbit is the WebGL fallback; no animation starts before hydration.
export default function Atmosphere() {
  const canvasRef=useRef<HTMLCanvasElement>(null);
  const pausedRef=useRef(false);
  const syncRef=useRef<(() => void) | null>(null);
  const [paused,setPaused]=useState(false);
  const [ready,setReady]=useState(false);
  useEffect(()=>{
    const canvas=canvasRef.current;
    if(!canvas) return;
    const reduced=matchMedia("(prefers-reduced-motion: reduce)");
    const root=document.documentElement;
    let gl: WebGLRenderingContext | null=null;
    try { gl=canvas.getContext("webgl",{alpha:true,premultipliedAlpha:false,antialias:false,powerPreference:"low-power"}); } catch { /* CSS fallback */ }
    let program:WebGLProgram|null=null, buffer:WebGLBuffer|null=null, vs:WebGLShader|null=null, fs:WebGLShader|null=null;
    let resolution:WebGLUniformLocation|null=null, time:WebGLUniformLocation|null=null;
    if(gl){
      const ctx=gl;
      function shader(type:number,source:string){const s=ctx.createShader(type); if(!s)return null;ctx.shaderSource(s,source);ctx.compileShader(s);if(!ctx.getShaderParameter(s,ctx.COMPILE_STATUS)){ctx.deleteShader(s);return null;}return s;}
      vs=shader(ctx.VERTEX_SHADER,"attribute vec2 p; void main(){gl_Position=vec4(p,0.,1.);}");
      fs=shader(ctx.FRAGMENT_SHADER,`precision mediump float; uniform vec2 resolution; uniform float time;
        void main(){vec2 uv=gl_FragCoord.xy/resolution; vec2 p=uv-vec2(.72,.50);p.x*=resolution.x/resolution.y;
        float r=length(p);float pulse=pow(max(0.,sin(r*26.-time*1.1)),20.);
        float edge=(1.-smoothstep(.15,.8,r));float alpha=min(.13,pulse*.10*edge);
        gl_FragColor=vec4(vec3(.90,.39,.16),alpha);}`);
      if(vs && fs){program=ctx.createProgram();if(program){ctx.attachShader(program,vs);ctx.attachShader(program,fs);ctx.linkProgram(program);if(!ctx.getProgramParameter(program,ctx.LINK_STATUS)){ctx.deleteProgram(program);program=null;}}}
      if(program){buffer=ctx.createBuffer();ctx.bindBuffer(ctx.ARRAY_BUFFER,buffer);ctx.bufferData(ctx.ARRAY_BUFFER,new Float32Array([-1,-1,1,-1,-1,1,1,1]),ctx.STATIC_DRAW);ctx.useProgram(program);const p=ctx.getAttribLocation(program,"p");ctx.enableVertexAttribArray(p);ctx.vertexAttribPointer(p,2,ctx.FLOAT,false,0,0);resolution=ctx.getUniformLocation(program,"resolution");time=ctx.getUniformLocation(program,"time");}
    }
    let frame=0,visible=false,last=0,elapsed=0;
    function draw(ms:number){
      if(gl && program && canvas){if(last)elapsed+=Math.min((ms-last)/1000,.05);last=ms;const dpr=Math.min(devicePixelRatio||1,1.25);const w=Math.max(1,Math.floor(canvas.clientWidth*dpr)),h=Math.max(1,Math.floor(canvas.clientHeight*dpr));if(canvas.width!==w||canvas.height!==h){canvas.width=w;canvas.height=h;gl.viewport(0,0,w,h);}gl.uniform2f(resolution,w,h);gl.uniform1f(time,elapsed);gl.drawArrays(gl.TRIANGLE_STRIP,0,4);}
      frame=requestAnimationFrame(draw);
    }
    function sync(){
      const active=visible&&!document.hidden&&!reduced.matches&&!pausedRef.current;
      root.classList.toggle("motion-enabled",!reduced.matches);
      if(active && gl && program && !frame)frame=requestAnimationFrame(draw);
      if(!active && frame){cancelAnimationFrame(frame);frame=0;last=0;}
    }
    syncRef.current=sync;setReady(true);
    const observer=typeof IntersectionObserver!=="undefined"?new IntersectionObserver(entries=>{visible=entries[0]?.isIntersecting??false;sync();}):null;
    if(observer)observer.observe(canvas);else visible=true;
    document.addEventListener("visibilitychange",sync);reduced.addEventListener("change",sync);sync();
    return ()=>{syncRef.current=null;cancelAnimationFrame(frame);observer?.disconnect();document.removeEventListener("visibilitychange",sync);reduced.removeEventListener("change",sync);root.classList.remove("motion-enabled","motion-paused");if(gl){gl.deleteBuffer(buffer);gl.deleteProgram(program);gl.deleteShader(vs);gl.deleteShader(fs);}};
  },[]);
  function toggle(){pausedRef.current=!pausedRef.current;setPaused(pausedRef.current);document.documentElement.classList.toggle("motion-paused",pausedRef.current);syncRef.current?.();}
  return <><canvas ref={canvasRef} className="atmosphere" aria-hidden="true"/><div className="orbit-scene" aria-hidden="true"><div className="orbit orbit-a"><i/></div><div className="orbit orbit-b"><i/></div><div className="orbit orbit-c"><i/></div><div className="scan-sweep"/><span className="orbit-cross cross-a">+</span><span className="orbit-cross cross-b">+</span></div>{ready && <button type="button" className="motion-control" aria-pressed={paused} onClick={toggle}><span aria-hidden="true">{paused ? "▶" : "Ⅱ"}</span> {paused ? "Resume motion" : "Pause motion"}</button>}</>;
}
