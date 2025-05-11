package lindell17

import "fmt"

var (
	// ErrGenerateSessionId is returned if the session id can't be generated.
	ErrGenerateSessionId = fmt.Errorf("unable to generate session id")
	// ErrInvalidState is returned if the instance's state is invalid.
	ErrInvalidState = fmt.Errorf("invalid state")
	// ErrUnknownMessage is returned if the message is unknown.
	ErrUnknownMessage = fmt.Errorf("unknown message")
	// ErrInvalidMessage is returned if the message is invalid.
	ErrInvalidMessage = fmt.Errorf("invalid message")
	// ErrWrongSender is returned if the sender is wrong.
	ErrWrongSender = fmt.Errorf("wrong sender")
	// ErrWrongRecipient is returned if the recipient is wrong.
	ErrWrongRecipient = fmt.Errorf("wrong recipient")
	// ErrWrongProtocol is returned if the protocol is wrong.
	ErrWrongProtocol = fmt.Errorf("wrong protocol")
)
