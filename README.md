# 基于quic的udp通讯server 和 client

#### server
```
import(  
    "fmt"
    server "github.com/gkyh/quic"
  )

const addr = "localhost:8000"    

func main() {

    srv := server.New(handler)
    srv.Run(addr)

}    
func handler(w server.Stream, buf []byte) {
   
   fmt.Println("server recv:",string(buf))
   w.Write([]byte("udp server message"))
}
```

#### client

```
import(  
    "fmt"
    "github.com/gkyh/quic"
  )

func main() {
    
    conn, err := udp.ClientConn(host, ProtoKey)
    if err != nil {
        fmt.Println("connt error:", err)
        panic(err)
    }
    
    _, err = conn.Send([]byte("hello udp server"))
    if err != nil {

        fmt.Println("send error:", err)
        panic(err)
    }
    
    recv, err := conn.Recv()
    if err != nil {

        fmt.Println("recv error:", err)
        panic(err)
    }
    fmt.Println(string(recv))
}

```

