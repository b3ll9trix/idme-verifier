package main

import(
	"net/http"
	"fmt"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"io"
)


type proof struct {
        Context []string `json:"@context"`
        Type string `json:"type"`
        Created string `json:"created"`
        Domain string `json:"domain"`
        Nonce string `json:"nonce"`
        ProofOfPurpose string `json:"proofPurpose"`
        VerificationMethod string `json:"verificationMethod"`
        ProofValue string `json:"proofValue"`
}

type VC struct {
        TypeID int `json:"typeID"`
        Type string `json:"type"`
        ID string `json:"id"`
        Proof proof `json:"proof"`
}

type HolderSignedVC struct {
	VC VC `json:"VC"`
        Proof proof `json:"proof"`
}

func isValidSignature(sign string) bool {
	f, err := os.Create("./tmp.json")
        if err != nil {
                fmt.Println(err)
        }
        defer f.Close()
        _, err = f.WriteString(string(sign))
        if err != nil {
                fmt.Println(err)
        }
        //Verifying using algoid                                      
        cmd := exec.Command("algoid", "verify", "tmp.json", "-i", "vp")
	out, err := cmd.CombinedOutput()
        if err != nil {
                fmt.Println(err)
        }

        return strings.Contains(string(out), "proof is valid")
}

func isUserVerified(hsvc *HolderSignedVC) bool {
	userSign := hsvc.Proof
	us, _ := json.Marshal(userSign)
	return isValidSignature(string(us))
}

func isIssuerVerified(hsvc *HolderSignedVC) bool {
        issuerSign := hsvc.VC.Proof
        is, _ := json.Marshal(issuerSign)
	return isValidSignature(string(is))
}

func VerifyVP(w http.ResponseWriter, req *http.Request){
	var hsvc HolderSignedVC
	b, _ := io.ReadAll(req.Body)
         err := json.Unmarshal(b, &hsvc)
         if err != nil {
                fmt.Println(err)
         }
	 //Extract user token and verify
	 //Extract issuer token and verify
	 if isIssuerVerified(&hsvc) && isUserVerified(&hsvc) {
		fmt.Fprintf(w, "The certificate is verfied")
	 } else {
		fmt.Fprintf(w, "The certificate is invalid and cannot be verified")
	 }


}

func main() {
    //Handlers    
    http.HandleFunc("/idme/verifier/verify/v1/vp", VerifyVP)
    fmt.Printf("Running on port 8088...");
    http.ListenAndServe("131.159.209.212:8088", nil)
}
