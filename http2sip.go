package main

import (
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"http2sip/auth"

	"github.com/jart/gosip/dialog"
	"github.com/jart/gosip/sdp"
	"github.com/jart/gosip/sip"
	"github.com/jart/gosip/util"

	"gopkg.in/yaml.v3"
)

type config struct {
	HttpPort    string        `yaml:"httpPort"`
	PenaltyTime time.Duration `yaml:"penaltyTime"`

	SipCallNumber     string        `yaml:"sipCallNumber"`
	SipServer         string        `yaml:"sipServer"`
	SipPort           uint16        `yaml:"sipPort"`
	SipUser           string        `yaml:"sipUser"`
	SipPassword       string        `yaml:"sipPassword"`
	SipReregisterTime time.Duration `yaml:"sipReregisterTime"`
}

var (
	registered = false
	calling    = false
	penalty    = false
	cfg        config
	cfgPath    string
	//go:embed "configExample.txt"
	configExample string

	sipAllow             = "INVITE, ACK, BYE, CANCEL, UPDATE, INFO, NOTIFY, OPTIONS"
	registerPkt          = &sip.Msg{}
	invitePkt            = &sip.Msg{}
	sipTo                = &sip.Addr{}
	sipFrom              = &sip.Addr{}
	sipContact           = &sip.Addr{}
	sipCseq              int
	sipAuthRegisterRetry int
	sipAuthInviteRetry   int
)

func GetOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP
}

func ternary(condition bool, a, b interface{}) interface{} {
	if condition {
		return a
	}
	return b
}

// sipHandler goroutine for handling messages and exit only on code failures
func sipHandler(transport *dialog.Transport) {
	log.Println("Starting sipHandler()...")
	var msg *sip.Msg
	var err error

	getAuth := func(answer *sip.Msg, request *sip.Msg, uri sip.URI, method string) (err error) {
		if answer.WWWAuthenticate != "" {
			request.Authorization, err = auth.GetDigestString(answer.WWWAuthenticate, cfg.SipUser, cfg.SipPassword, uri.String(), method)
		} else if answer.ProxyAuthenticate != "" {
			request.ProxyAuthorization, err = auth.GetDigestString(answer.ProxyAuthenticate, cfg.SipUser, cfg.SipPassword, uri.String(), method)
		} else {
			err = errors.New("WWW-Authenticate or Proxy-Authenticate headers NOT FOUND")
		}
		return err
	}

	for {
		select {
		case err = <-transport.E:
			log.Println("SIP recv failed:", err)

		case msg = <-transport.C:
			log.Printf("SIP MESSAGE: %s -> %d (%s)\n", msg.CSeqMethod, msg.Status, sip.Phrase(msg.Status))

			if msg.IsResponse() {
				switch msg.Status {
				case sip.StatusUnauthorized:
					msg.Contact = sipContact
					if msg.CSeq == registerPkt.CSeq {
						registered = false
						registerPkt.Authorization = ""

						if sipAuthRegisterRetry > 0 {
							sipCseq++
							registerPkt.CSeq = sipCseq
							// ACK not needed on REGISTER
							uri := sip.URI{Scheme: "sip", Host: cfg.SipServer}
							err = getAuth(msg, registerPkt, uri, sip.MethodRegister)
							if err != nil {
								log.Println(err)
								break
							}
							err = transport.Send(registerPkt)
							if err != nil {
								log.Println(err)
							}
							time.Sleep(1 * time.Second)
							sipAuthRegisterRetry--
						} else {
							log.Println("Number of Authorization requests exceeded (wrong password?)")
						}
					}
					if msg.CSeq == invitePkt.CSeq {
						// send ACK for unauthorized message
						invitePkt.Authorization = ""

						err = transport.Send(dialog.NewAck(msg, invitePkt))
						if err != nil {
							log.Fatal("SIP send failed:", err)
						}

						if sipAuthInviteRetry > 0 {
							sipCseq++
							invitePkt.CSeq = sipCseq
							uri := sip.URI{Scheme: "sip", User: cfg.SipCallNumber, Host: cfg.SipServer}

							err = getAuth(msg, invitePkt, uri, sip.MethodInvite)
							if err != nil {
								log.Println(err)
								break
							}

							err = transport.Send(invitePkt)
							if err != nil {
								log.Println(err)
							}
							time.Sleep(1 * time.Second)
							sipAuthInviteRetry--
						} else {
							log.Println("Number of Authorization requests exceeded (wrong password?)")
						}
					}

				case sip.StatusSessionProgress:
					log.Printf("Probably Ringing!")
					if msg.CSeq == invitePkt.CSeq {
						// send SIP CANCEL
						invitePkt.Authorization = ""
						cancel := dialog.NewCancel(invitePkt)
						err = transport.Send(cancel)
						if err != nil {
							log.Println("SIP send failed:", err)
						}
					}

				case sip.StatusOK:
					if msg.CSeq == registerPkt.CSeq {
						switch msg.CSeqMethod {
						case sip.MethodRegister:
							log.Println("Registered!")
							log.Println("Expires: ", msg.Expires)
							registered = true
						case sip.MethodInvite:
							log.Println("Answered!")
						case sip.MethodBye:
							log.Println("Hungup!")
						case sip.MethodCancel:
							log.Println("Cancelled!")
						}
					}
					if msg.CSeq == invitePkt.CSeq {
						switch msg.CSeqMethod {
						case sip.MethodRegister:
							log.Println("Registered!")
						case sip.MethodInvite:
							log.Println("Answered!")
							invitePkt.Authorization = ""
							cancel := dialog.NewCancel(invitePkt)
							err = transport.Send(cancel)
							if err != nil {
								log.Println("SIP send failed:", err)
							}
						case sip.MethodBye:
							log.Println("Hungup!")
						case sip.MethodCancel:
							log.Println("Cancelled!")
							calling = false
							msg.Contact = sipContact
							err = transport.Send(dialog.NewAck(msg, invitePkt))
							if err != nil {
								log.Println("SIP send failed:", err)
							}
						}
					}

				case sip.StatusRequestTerminated:
					msg.Contact = sipContact
					err = transport.Send(dialog.NewAck(msg, invitePkt))
					if err != nil {
						log.Println("SIP send failed:", err)
					}

				case sip.StatusForbidden:
					if msg.CSeq == invitePkt.CSeq {
						// on forbidden reset register and calling states
						registered = false
						calling = false
					}
				}
			} else {
				if msg.Method == "BYE" {
					log.Printf("%s: Remote Hangup!\n", msg.Method)
					err = transport.Send(dialog.NewResponse(msg, sip.StatusOK))
					if err != nil {
						log.Println("SIP send failed:", err)
					}
				}
			}
		}
	}
}

// Register send REGISTER and resend it after configured time interval
func Register(transport *dialog.Transport) {
	sipAuthRegisterRetry = 3
	// REGISTER packet
	regSipTo := sipTo
	regSipTo.Uri.User = cfg.SipUser
	registerPkt = dialog.NewRequest(transport, sip.MethodRegister, regSipTo, sipFrom)
	registerPkt.Expires = 300
	registerPkt.Allow = sipAllow
	registerPkt.CSeq = sipCseq

	err := transport.Send(registerPkt)
	if err != nil {
		log.Println(err)
	}

	resends := 1
	resend := registerPkt
	resendTimer := time.After(cfg.SipReregisterTime)

	for {
		select {
		case <-resendTimer:
			sipCseq++
			resend.CSeq = sipCseq
			registerPkt = resend
			err = transport.Send(resend)
			if err != nil {
				log.Println("SIP send failed:", err)
			}
			log.Printf("RE-REGISTER NUMBER: %d\n", resends)
			sipAuthRegisterRetry = 1 // for RE-REGISTER work
			resends++
			resendTimer = time.After(cfg.SipReregisterTime)
		}
	}
}

// Call make a SIP call (INVITE) to configured phone number
func Call(number string, transport *dialog.Transport) {
	if calling {
		log.Println("Already calling...")
		return
	}
	sipAuthInviteRetry = 3
	calling = true
	log.Println("REGISTERED:", registered)

	// INVITE packet
	inviteSipTo := sipTo
	inviteSipTo.Uri.User = number
	invitePkt = dialog.NewRequest(transport, sip.MethodInvite, inviteSipTo, sipFrom)
	invitePkt.Allow = sipAllow
	invitePkt.Payload = sdp.New(&net.UDPAddr{IP: GetOutboundIP(), Port: 20000}, sdp.ULAWCodec, sdp.DTMFCodec)
	sipCseq++
	invitePkt.CSeq = sipCseq

	exitTimeout := false
	exitTime := 15 * time.Second
	exitTimer := time.AfterFunc(exitTime, func() {
		exitTimeout = true
	})
	defer exitTimer.Stop()

	// reset calling state on timeout
	deathTime := 30 * time.Second
	time.AfterFunc(deathTime, func() {
		if calling {
			log.Println("Seems calling timed out, resetting states.")
			calling = false
		}
	})

	try := 1
	waitTime := 5 * time.Second
	for registered == false {
		log.Printf("Not registered (%d try), waiting %v\n", try, waitTime)
		try++
		time.Sleep(waitTime)
		if exitTimeout {
			log.Println("Timeout registration, calling failed.")
			calling = false
			return
		}
	}

	// make call
	log.Println("Calling...")
	err := transport.Send(invitePkt)
	if err != nil {
		log.Println(err)
		calling = false
		return
	}
	return
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// loading settings from config.yml
	flag.StringVar(&cfgPath, "cfg", "config.yml", "path to config file")
	flag.Parse()
	file, err := os.Open(cfgPath)
	if os.IsNotExist(err) {
		fmt.Print("Config doesn't exist, example content of config.yml: \n\n")
		fmt.Println(configExample)
		return
	}
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	log.Printf("using config file '%s'\n", file.Name())

	d := yaml.NewDecoder(file)

	// Start YAML decoding from file
	if err := d.Decode(&cfg); err != nil {
		return
	}
	err = file.Close()
	if err != nil {
		return
	}

	// publishing SIP data
	sipTo = &sip.Addr{
		Uri: &sip.URI{
			//User: cfg.SipUser,
			Host: cfg.SipServer,
			Port: cfg.SipPort,
		},
	}
	sipFrom = &sip.Addr{
		Uri: &sip.URI{
			User: cfg.SipUser,
			Host: cfg.SipServer,
		},
	}
	sipContact = &sip.Addr{ // replace contact for properly work NewAck() method
		Uri: &sip.URI{
			User: cfg.SipUser,
			Host: cfg.SipServer,
			Port: cfg.SipPort,
		},
	}
	myContact := &sip.Addr{
		Uri: &sip.URI{
			User:  cfg.SipUser,
			Host:  GetOutboundIP().String(),
			Param: &sip.URIParam{Name: "ob"},
		},
	}
	sipCseq = util.GenerateCSeq()

	// making SIP transport
	transport, err := dialog.NewTransport(myContact)
	if err != nil {
		log.Println(err)
		return
	}

	// running message handler and SIP REGISTER initialization
	go sipHandler(transport)
	go Register(transport)

	http.HandleFunc("/open", func(w http.ResponseWriter, r *http.Request) {
		clientRemote := ternary(len(r.Header.Get("X-Forwarded-For")) > 0, r.Header.Get("X-Forwarded-For"), r.RemoteAddr)

		log.Printf("HTTP %s : %s (%s) -> %s", r.Method, clientRemote, r.UserAgent(), html.EscapeString(r.URL.Path))

		if penalty {
			log.Println("Penalty ACTIVE, ignoring request.")
			_, err := fmt.Fprintf(w, fmt.Sprintf("ERROR: Too fast (1 per %v), maybe gate allready opened? ;-o", cfg.PenaltyTime))
			if err != nil {
				log.Printf("error: %s", err)
				return
			}
			return
		}

		if !calling {
			_, err := fmt.Fprintf(w, "Opening... ;-P")
			if err != nil {
				log.Printf("error: %s\n", err)
				return
			}

			penalty = true
			time.AfterFunc(cfg.PenaltyTime, func() {
				log.Println("Penalty time over.")
				penalty = false
			})

			log.Printf("Will call to %v\n", cfg.SipCallNumber)

			// making call
			go Call(cfg.SipCallNumber, transport)
		} else {
			_, err := fmt.Fprintf(w, "ERROR: Someone allready opening now or internal error ;-E")
			if err != nil {
				log.Printf("error: %s\n", err)
				return
			}
		}
	})

	log.Printf("Listening on any: %s", cfg.HttpPort)
	log.Fatal(http.ListenAndServe(":"+cfg.HttpPort, nil))
}
