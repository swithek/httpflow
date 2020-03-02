// Code generated by moq; DO NOT EDIT.
// github.com/matryer/moq

package user

import (
	"context"
	"github.com/swithek/httpflow"
	"sync"
)

var (
	lockDatabaseMockCreate       sync.RWMutex
	lockDatabaseMockDeleteByID   sync.RWMutex
	lockDatabaseMockFetchByEmail sync.RWMutex
	lockDatabaseMockFetchByID    sync.RWMutex
	lockDatabaseMockFetchMany    sync.RWMutex
	lockDatabaseMockStats        sync.RWMutex
	lockDatabaseMockUpdate       sync.RWMutex
)

// Ensure, that DatabaseMock does implement Database.
// If this is not the case, regenerate this file with moq.
var _ Database = &DatabaseMock{}

// DatabaseMock is a mock implementation of Database.
//
//     func TestSomethingThatUsesDatabase(t *testing.T) {
//
//         // make and configure a mocked Database
//         mockedDatabase := &DatabaseMock{
//             CreateFunc: func(ctx context.Context, usr User) error {
// 	               panic("mock out the Create method")
//             },
//             DeleteByIDFunc: func(ctx context.Context, id string) error {
// 	               panic("mock out the DeleteByID method")
//             },
//             FetchByEmailFunc: func(ctx context.Context, eml string) (User, error) {
// 	               panic("mock out the FetchByEmail method")
//             },
//             FetchByIDFunc: func(ctx context.Context, id string) (User, error) {
// 	               panic("mock out the FetchByID method")
//             },
//             FetchManyFunc: func(ctx context.Context, qr httpflow.Query) ([]User, error) {
// 	               panic("mock out the FetchMany method")
//             },
//             StatsFunc: func(ctx context.Context) (Stats, error) {
// 	               panic("mock out the Stats method")
//             },
//             UpdateFunc: func(ctx context.Context, usr User) error {
// 	               panic("mock out the Update method")
//             },
//         }
//
//         // use mockedDatabase in code that requires Database
//         // and then make assertions.
//
//     }
type DatabaseMock struct {
	// CreateFunc mocks the Create method.
	CreateFunc func(ctx context.Context, usr User) error

	// DeleteByIDFunc mocks the DeleteByID method.
	DeleteByIDFunc func(ctx context.Context, id string) error

	// FetchByEmailFunc mocks the FetchByEmail method.
	FetchByEmailFunc func(ctx context.Context, eml string) (User, error)

	// FetchByIDFunc mocks the FetchByID method.
	FetchByIDFunc func(ctx context.Context, id string) (User, error)

	// FetchManyFunc mocks the FetchMany method.
	FetchManyFunc func(ctx context.Context, qr httpflow.Query) ([]User, error)

	// StatsFunc mocks the Stats method.
	StatsFunc func(ctx context.Context) (Stats, error)

	// UpdateFunc mocks the Update method.
	UpdateFunc func(ctx context.Context, usr User) error

	// calls tracks calls to the methods.
	calls struct {
		// Create holds details about calls to the Create method.
		Create []struct {
			// Ctx is the ctx argument value.
			Ctx context.Context
			// Usr is the usr argument value.
			Usr User
		}
		// DeleteByID holds details about calls to the DeleteByID method.
		DeleteByID []struct {
			// Ctx is the ctx argument value.
			Ctx context.Context
			// ID is the id argument value.
			ID string
		}
		// FetchByEmail holds details about calls to the FetchByEmail method.
		FetchByEmail []struct {
			// Ctx is the ctx argument value.
			Ctx context.Context
			// Eml is the eml argument value.
			Eml string
		}
		// FetchByID holds details about calls to the FetchByID method.
		FetchByID []struct {
			// Ctx is the ctx argument value.
			Ctx context.Context
			// ID is the id argument value.
			ID string
		}
		// FetchMany holds details about calls to the FetchMany method.
		FetchMany []struct {
			// Ctx is the ctx argument value.
			Ctx context.Context
			// Qr is the qr argument value.
			Qr httpflow.Query
		}
		// Stats holds details about calls to the Stats method.
		Stats []struct {
			// Ctx is the ctx argument value.
			Ctx context.Context
		}
		// Update holds details about calls to the Update method.
		Update []struct {
			// Ctx is the ctx argument value.
			Ctx context.Context
			// Usr is the usr argument value.
			Usr User
		}
	}
}

// Create calls CreateFunc.
func (mock *DatabaseMock) Create(ctx context.Context, usr User) error {
	if mock.CreateFunc == nil {
		panic("DatabaseMock.CreateFunc: method is nil but Database.Create was just called")
	}
	callInfo := struct {
		Ctx context.Context
		Usr User
	}{
		Ctx: ctx,
		Usr: usr,
	}
	lockDatabaseMockCreate.Lock()
	mock.calls.Create = append(mock.calls.Create, callInfo)
	lockDatabaseMockCreate.Unlock()
	return mock.CreateFunc(ctx, usr)
}

// CreateCalls gets all the calls that were made to Create.
// Check the length with:
//     len(mockedDatabase.CreateCalls())
func (mock *DatabaseMock) CreateCalls() []struct {
	Ctx context.Context
	Usr User
} {
	var calls []struct {
		Ctx context.Context
		Usr User
	}
	lockDatabaseMockCreate.RLock()
	calls = mock.calls.Create
	lockDatabaseMockCreate.RUnlock()
	return calls
}

// DeleteByID calls DeleteByIDFunc.
func (mock *DatabaseMock) DeleteByID(ctx context.Context, id string) error {
	if mock.DeleteByIDFunc == nil {
		panic("DatabaseMock.DeleteByIDFunc: method is nil but Database.DeleteByID was just called")
	}
	callInfo := struct {
		Ctx context.Context
		ID  string
	}{
		Ctx: ctx,
		ID:  id,
	}
	lockDatabaseMockDeleteByID.Lock()
	mock.calls.DeleteByID = append(mock.calls.DeleteByID, callInfo)
	lockDatabaseMockDeleteByID.Unlock()
	return mock.DeleteByIDFunc(ctx, id)
}

// DeleteByIDCalls gets all the calls that were made to DeleteByID.
// Check the length with:
//     len(mockedDatabase.DeleteByIDCalls())
func (mock *DatabaseMock) DeleteByIDCalls() []struct {
	Ctx context.Context
	ID  string
} {
	var calls []struct {
		Ctx context.Context
		ID  string
	}
	lockDatabaseMockDeleteByID.RLock()
	calls = mock.calls.DeleteByID
	lockDatabaseMockDeleteByID.RUnlock()
	return calls
}

// FetchByEmail calls FetchByEmailFunc.
func (mock *DatabaseMock) FetchByEmail(ctx context.Context, eml string) (User, error) {
	if mock.FetchByEmailFunc == nil {
		panic("DatabaseMock.FetchByEmailFunc: method is nil but Database.FetchByEmail was just called")
	}
	callInfo := struct {
		Ctx context.Context
		Eml string
	}{
		Ctx: ctx,
		Eml: eml,
	}
	lockDatabaseMockFetchByEmail.Lock()
	mock.calls.FetchByEmail = append(mock.calls.FetchByEmail, callInfo)
	lockDatabaseMockFetchByEmail.Unlock()
	return mock.FetchByEmailFunc(ctx, eml)
}

// FetchByEmailCalls gets all the calls that were made to FetchByEmail.
// Check the length with:
//     len(mockedDatabase.FetchByEmailCalls())
func (mock *DatabaseMock) FetchByEmailCalls() []struct {
	Ctx context.Context
	Eml string
} {
	var calls []struct {
		Ctx context.Context
		Eml string
	}
	lockDatabaseMockFetchByEmail.RLock()
	calls = mock.calls.FetchByEmail
	lockDatabaseMockFetchByEmail.RUnlock()
	return calls
}

// FetchByID calls FetchByIDFunc.
func (mock *DatabaseMock) FetchByID(ctx context.Context, id string) (User, error) {
	if mock.FetchByIDFunc == nil {
		panic("DatabaseMock.FetchByIDFunc: method is nil but Database.FetchByID was just called")
	}
	callInfo := struct {
		Ctx context.Context
		ID  string
	}{
		Ctx: ctx,
		ID:  id,
	}
	lockDatabaseMockFetchByID.Lock()
	mock.calls.FetchByID = append(mock.calls.FetchByID, callInfo)
	lockDatabaseMockFetchByID.Unlock()
	return mock.FetchByIDFunc(ctx, id)
}

// FetchByIDCalls gets all the calls that were made to FetchByID.
// Check the length with:
//     len(mockedDatabase.FetchByIDCalls())
func (mock *DatabaseMock) FetchByIDCalls() []struct {
	Ctx context.Context
	ID  string
} {
	var calls []struct {
		Ctx context.Context
		ID  string
	}
	lockDatabaseMockFetchByID.RLock()
	calls = mock.calls.FetchByID
	lockDatabaseMockFetchByID.RUnlock()
	return calls
}

// FetchMany calls FetchManyFunc.
func (mock *DatabaseMock) FetchMany(ctx context.Context, qr httpflow.Query) ([]User, error) {
	if mock.FetchManyFunc == nil {
		panic("DatabaseMock.FetchManyFunc: method is nil but Database.FetchMany was just called")
	}
	callInfo := struct {
		Ctx context.Context
		Qr  httpflow.Query
	}{
		Ctx: ctx,
		Qr:  qr,
	}
	lockDatabaseMockFetchMany.Lock()
	mock.calls.FetchMany = append(mock.calls.FetchMany, callInfo)
	lockDatabaseMockFetchMany.Unlock()
	return mock.FetchManyFunc(ctx, qr)
}

// FetchManyCalls gets all the calls that were made to FetchMany.
// Check the length with:
//     len(mockedDatabase.FetchManyCalls())
func (mock *DatabaseMock) FetchManyCalls() []struct {
	Ctx context.Context
	Qr  httpflow.Query
} {
	var calls []struct {
		Ctx context.Context
		Qr  httpflow.Query
	}
	lockDatabaseMockFetchMany.RLock()
	calls = mock.calls.FetchMany
	lockDatabaseMockFetchMany.RUnlock()
	return calls
}

// Stats calls StatsFunc.
func (mock *DatabaseMock) Stats(ctx context.Context) (Stats, error) {
	if mock.StatsFunc == nil {
		panic("DatabaseMock.StatsFunc: method is nil but Database.Stats was just called")
	}
	callInfo := struct {
		Ctx context.Context
	}{
		Ctx: ctx,
	}
	lockDatabaseMockStats.Lock()
	mock.calls.Stats = append(mock.calls.Stats, callInfo)
	lockDatabaseMockStats.Unlock()
	return mock.StatsFunc(ctx)
}

// StatsCalls gets all the calls that were made to Stats.
// Check the length with:
//     len(mockedDatabase.StatsCalls())
func (mock *DatabaseMock) StatsCalls() []struct {
	Ctx context.Context
} {
	var calls []struct {
		Ctx context.Context
	}
	lockDatabaseMockStats.RLock()
	calls = mock.calls.Stats
	lockDatabaseMockStats.RUnlock()
	return calls
}

// Update calls UpdateFunc.
func (mock *DatabaseMock) Update(ctx context.Context, usr User) error {
	if mock.UpdateFunc == nil {
		panic("DatabaseMock.UpdateFunc: method is nil but Database.Update was just called")
	}
	callInfo := struct {
		Ctx context.Context
		Usr User
	}{
		Ctx: ctx,
		Usr: usr,
	}
	lockDatabaseMockUpdate.Lock()
	mock.calls.Update = append(mock.calls.Update, callInfo)
	lockDatabaseMockUpdate.Unlock()
	return mock.UpdateFunc(ctx, usr)
}

// UpdateCalls gets all the calls that were made to Update.
// Check the length with:
//     len(mockedDatabase.UpdateCalls())
func (mock *DatabaseMock) UpdateCalls() []struct {
	Ctx context.Context
	Usr User
} {
	var calls []struct {
		Ctx context.Context
		Usr User
	}
	lockDatabaseMockUpdate.RLock()
	calls = mock.calls.Update
	lockDatabaseMockUpdate.RUnlock()
	return calls
}

var (
	lockEmailSenderMockSendAccountActivation sync.RWMutex
	lockEmailSenderMockSendAccountDeleted    sync.RWMutex
	lockEmailSenderMockSendEmailChanged      sync.RWMutex
	lockEmailSenderMockSendEmailVerification sync.RWMutex
	lockEmailSenderMockSendPasswordChanged   sync.RWMutex
	lockEmailSenderMockSendRecovery          sync.RWMutex
)

// Ensure, that EmailSenderMock does implement EmailSender.
// If this is not the case, regenerate this file with moq.
var _ EmailSender = &EmailSenderMock{}

// EmailSenderMock is a mock implementation of EmailSender.
//
//     func TestSomethingThatUsesEmailSender(t *testing.T) {
//
//         // make and configure a mocked EmailSender
//         mockedEmailSender := &EmailSenderMock{
//             SendAccountActivationFunc: func(ctx context.Context, eml string, tok string)  {
// 	               panic("mock out the SendAccountActivation method")
//             },
//             SendAccountDeletedFunc: func(ctx context.Context, eml string)  {
// 	               panic("mock out the SendAccountDeleted method")
//             },
//             SendEmailChangedFunc: func(ctx context.Context, oEml string, nEml string)  {
// 	               panic("mock out the SendEmailChanged method")
//             },
//             SendEmailVerificationFunc: func(ctx context.Context, eml string, tok string)  {
// 	               panic("mock out the SendEmailVerification method")
//             },
//             SendPasswordChangedFunc: func(ctx context.Context, eml string, recov bool)  {
// 	               panic("mock out the SendPasswordChanged method")
//             },
//             SendRecoveryFunc: func(ctx context.Context, eml string, tok string)  {
// 	               panic("mock out the SendRecovery method")
//             },
//         }
//
//         // use mockedEmailSender in code that requires EmailSender
//         // and then make assertions.
//
//     }
type EmailSenderMock struct {
	// SendAccountActivationFunc mocks the SendAccountActivation method.
	SendAccountActivationFunc func(ctx context.Context, eml string, tok string)

	// SendAccountDeletedFunc mocks the SendAccountDeleted method.
	SendAccountDeletedFunc func(ctx context.Context, eml string)

	// SendEmailChangedFunc mocks the SendEmailChanged method.
	SendEmailChangedFunc func(ctx context.Context, oEml string, nEml string)

	// SendEmailVerificationFunc mocks the SendEmailVerification method.
	SendEmailVerificationFunc func(ctx context.Context, eml string, tok string)

	// SendPasswordChangedFunc mocks the SendPasswordChanged method.
	SendPasswordChangedFunc func(ctx context.Context, eml string, recov bool)

	// SendRecoveryFunc mocks the SendRecovery method.
	SendRecoveryFunc func(ctx context.Context, eml string, tok string)

	// calls tracks calls to the methods.
	calls struct {
		// SendAccountActivation holds details about calls to the SendAccountActivation method.
		SendAccountActivation []struct {
			// Ctx is the ctx argument value.
			Ctx context.Context
			// Eml is the eml argument value.
			Eml string
			// Tok is the tok argument value.
			Tok string
		}
		// SendAccountDeleted holds details about calls to the SendAccountDeleted method.
		SendAccountDeleted []struct {
			// Ctx is the ctx argument value.
			Ctx context.Context
			// Eml is the eml argument value.
			Eml string
		}
		// SendEmailChanged holds details about calls to the SendEmailChanged method.
		SendEmailChanged []struct {
			// Ctx is the ctx argument value.
			Ctx context.Context
			// OEml is the oEml argument value.
			OEml string
			// NEml is the nEml argument value.
			NEml string
		}
		// SendEmailVerification holds details about calls to the SendEmailVerification method.
		SendEmailVerification []struct {
			// Ctx is the ctx argument value.
			Ctx context.Context
			// Eml is the eml argument value.
			Eml string
			// Tok is the tok argument value.
			Tok string
		}
		// SendPasswordChanged holds details about calls to the SendPasswordChanged method.
		SendPasswordChanged []struct {
			// Ctx is the ctx argument value.
			Ctx context.Context
			// Eml is the eml argument value.
			Eml string
			// Recov is the recov argument value.
			Recov bool
		}
		// SendRecovery holds details about calls to the SendRecovery method.
		SendRecovery []struct {
			// Ctx is the ctx argument value.
			Ctx context.Context
			// Eml is the eml argument value.
			Eml string
			// Tok is the tok argument value.
			Tok string
		}
	}
}

// SendAccountActivation calls SendAccountActivationFunc.
func (mock *EmailSenderMock) SendAccountActivation(ctx context.Context, eml string, tok string) {
	if mock.SendAccountActivationFunc == nil {
		panic("EmailSenderMock.SendAccountActivationFunc: method is nil but EmailSender.SendAccountActivation was just called")
	}
	callInfo := struct {
		Ctx context.Context
		Eml string
		Tok string
	}{
		Ctx: ctx,
		Eml: eml,
		Tok: tok,
	}
	lockEmailSenderMockSendAccountActivation.Lock()
	mock.calls.SendAccountActivation = append(mock.calls.SendAccountActivation, callInfo)
	lockEmailSenderMockSendAccountActivation.Unlock()
	mock.SendAccountActivationFunc(ctx, eml, tok)
}

// SendAccountActivationCalls gets all the calls that were made to SendAccountActivation.
// Check the length with:
//     len(mockedEmailSender.SendAccountActivationCalls())
func (mock *EmailSenderMock) SendAccountActivationCalls() []struct {
	Ctx context.Context
	Eml string
	Tok string
} {
	var calls []struct {
		Ctx context.Context
		Eml string
		Tok string
	}
	lockEmailSenderMockSendAccountActivation.RLock()
	calls = mock.calls.SendAccountActivation
	lockEmailSenderMockSendAccountActivation.RUnlock()
	return calls
}

// SendAccountDeleted calls SendAccountDeletedFunc.
func (mock *EmailSenderMock) SendAccountDeleted(ctx context.Context, eml string) {
	if mock.SendAccountDeletedFunc == nil {
		panic("EmailSenderMock.SendAccountDeletedFunc: method is nil but EmailSender.SendAccountDeleted was just called")
	}
	callInfo := struct {
		Ctx context.Context
		Eml string
	}{
		Ctx: ctx,
		Eml: eml,
	}
	lockEmailSenderMockSendAccountDeleted.Lock()
	mock.calls.SendAccountDeleted = append(mock.calls.SendAccountDeleted, callInfo)
	lockEmailSenderMockSendAccountDeleted.Unlock()
	mock.SendAccountDeletedFunc(ctx, eml)
}

// SendAccountDeletedCalls gets all the calls that were made to SendAccountDeleted.
// Check the length with:
//     len(mockedEmailSender.SendAccountDeletedCalls())
func (mock *EmailSenderMock) SendAccountDeletedCalls() []struct {
	Ctx context.Context
	Eml string
} {
	var calls []struct {
		Ctx context.Context
		Eml string
	}
	lockEmailSenderMockSendAccountDeleted.RLock()
	calls = mock.calls.SendAccountDeleted
	lockEmailSenderMockSendAccountDeleted.RUnlock()
	return calls
}

// SendEmailChanged calls SendEmailChangedFunc.
func (mock *EmailSenderMock) SendEmailChanged(ctx context.Context, oEml string, nEml string) {
	if mock.SendEmailChangedFunc == nil {
		panic("EmailSenderMock.SendEmailChangedFunc: method is nil but EmailSender.SendEmailChanged was just called")
	}
	callInfo := struct {
		Ctx  context.Context
		OEml string
		NEml string
	}{
		Ctx:  ctx,
		OEml: oEml,
		NEml: nEml,
	}
	lockEmailSenderMockSendEmailChanged.Lock()
	mock.calls.SendEmailChanged = append(mock.calls.SendEmailChanged, callInfo)
	lockEmailSenderMockSendEmailChanged.Unlock()
	mock.SendEmailChangedFunc(ctx, oEml, nEml)
}

// SendEmailChangedCalls gets all the calls that were made to SendEmailChanged.
// Check the length with:
//     len(mockedEmailSender.SendEmailChangedCalls())
func (mock *EmailSenderMock) SendEmailChangedCalls() []struct {
	Ctx  context.Context
	OEml string
	NEml string
} {
	var calls []struct {
		Ctx  context.Context
		OEml string
		NEml string
	}
	lockEmailSenderMockSendEmailChanged.RLock()
	calls = mock.calls.SendEmailChanged
	lockEmailSenderMockSendEmailChanged.RUnlock()
	return calls
}

// SendEmailVerification calls SendEmailVerificationFunc.
func (mock *EmailSenderMock) SendEmailVerification(ctx context.Context, eml string, tok string) {
	if mock.SendEmailVerificationFunc == nil {
		panic("EmailSenderMock.SendEmailVerificationFunc: method is nil but EmailSender.SendEmailVerification was just called")
	}
	callInfo := struct {
		Ctx context.Context
		Eml string
		Tok string
	}{
		Ctx: ctx,
		Eml: eml,
		Tok: tok,
	}
	lockEmailSenderMockSendEmailVerification.Lock()
	mock.calls.SendEmailVerification = append(mock.calls.SendEmailVerification, callInfo)
	lockEmailSenderMockSendEmailVerification.Unlock()
	mock.SendEmailVerificationFunc(ctx, eml, tok)
}

// SendEmailVerificationCalls gets all the calls that were made to SendEmailVerification.
// Check the length with:
//     len(mockedEmailSender.SendEmailVerificationCalls())
func (mock *EmailSenderMock) SendEmailVerificationCalls() []struct {
	Ctx context.Context
	Eml string
	Tok string
} {
	var calls []struct {
		Ctx context.Context
		Eml string
		Tok string
	}
	lockEmailSenderMockSendEmailVerification.RLock()
	calls = mock.calls.SendEmailVerification
	lockEmailSenderMockSendEmailVerification.RUnlock()
	return calls
}

// SendPasswordChanged calls SendPasswordChangedFunc.
func (mock *EmailSenderMock) SendPasswordChanged(ctx context.Context, eml string, recov bool) {
	if mock.SendPasswordChangedFunc == nil {
		panic("EmailSenderMock.SendPasswordChangedFunc: method is nil but EmailSender.SendPasswordChanged was just called")
	}
	callInfo := struct {
		Ctx   context.Context
		Eml   string
		Recov bool
	}{
		Ctx:   ctx,
		Eml:   eml,
		Recov: recov,
	}
	lockEmailSenderMockSendPasswordChanged.Lock()
	mock.calls.SendPasswordChanged = append(mock.calls.SendPasswordChanged, callInfo)
	lockEmailSenderMockSendPasswordChanged.Unlock()
	mock.SendPasswordChangedFunc(ctx, eml, recov)
}

// SendPasswordChangedCalls gets all the calls that were made to SendPasswordChanged.
// Check the length with:
//     len(mockedEmailSender.SendPasswordChangedCalls())
func (mock *EmailSenderMock) SendPasswordChangedCalls() []struct {
	Ctx   context.Context
	Eml   string
	Recov bool
} {
	var calls []struct {
		Ctx   context.Context
		Eml   string
		Recov bool
	}
	lockEmailSenderMockSendPasswordChanged.RLock()
	calls = mock.calls.SendPasswordChanged
	lockEmailSenderMockSendPasswordChanged.RUnlock()
	return calls
}

// SendRecovery calls SendRecoveryFunc.
func (mock *EmailSenderMock) SendRecovery(ctx context.Context, eml string, tok string) {
	if mock.SendRecoveryFunc == nil {
		panic("EmailSenderMock.SendRecoveryFunc: method is nil but EmailSender.SendRecovery was just called")
	}
	callInfo := struct {
		Ctx context.Context
		Eml string
		Tok string
	}{
		Ctx: ctx,
		Eml: eml,
		Tok: tok,
	}
	lockEmailSenderMockSendRecovery.Lock()
	mock.calls.SendRecovery = append(mock.calls.SendRecovery, callInfo)
	lockEmailSenderMockSendRecovery.Unlock()
	mock.SendRecoveryFunc(ctx, eml, tok)
}

// SendRecoveryCalls gets all the calls that were made to SendRecovery.
// Check the length with:
//     len(mockedEmailSender.SendRecoveryCalls())
func (mock *EmailSenderMock) SendRecoveryCalls() []struct {
	Ctx context.Context
	Eml string
	Tok string
} {
	var calls []struct {
		Ctx context.Context
		Eml string
		Tok string
	}
	lockEmailSenderMockSendRecovery.RLock()
	calls = mock.calls.SendRecovery
	lockEmailSenderMockSendRecovery.RUnlock()
	return calls
}
