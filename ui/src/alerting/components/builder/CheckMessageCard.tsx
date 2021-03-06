// Libraries
import React, {FC} from 'react'
import {connect} from 'react-redux'

// Components
import {
  ComponentSize,
  TextArea,
  AutoComplete,
  Wrap,
} from '@influxdata/clockface'
import BuilderCard from 'src/timeMachine/components/builderCard/BuilderCard'

// Actions & Selectors
import {updateTimeMachineCheck} from 'src/timeMachine/actions'
import {getActiveTimeMachine} from 'src/timeMachine/selectors'

// Types
import {Check, AppState} from 'src/types'

interface DispatchProps {
  onUpdateTimeMachineCheck: typeof updateTimeMachineCheck
}

interface StateProps {
  check: Partial<Check>
}

type Props = DispatchProps & StateProps

const CheckMessageCard: FC<Props> = ({check, onUpdateTimeMachineCheck}) => {
  const handleChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>
  ) => {
    onUpdateTimeMachineCheck({[e.target.name]: e.target.value})
  }

  return (
    <BuilderCard
      testID="builder-message"
      className="alert-builder--card alert-builder--message-card"
    >
      <BuilderCard.Header title="Status Message Template" />
      <BuilderCard.Body addPadding={true} autoHideScrollbars={true}>
        <TextArea
          className="alert-builder--message-template"
          autoFocus={false}
          autocomplete={AutoComplete.Off}
          form=""
          maxLength={500}
          minLength={5}
          name="statusMessageTemplate"
          onChange={handleChange}
          readOnly={false}
          required={false}
          size={ComponentSize.Medium}
          spellCheck={false}
          testID="status-message-textarea"
          value={check.statusMessageTemplate}
          wrap={Wrap.Soft}
          placeholder="This template what this Check will use to write status messages"
        />
        <div className="alert-builder--message-help">
          <p>
            You can use any columns from your query as well as the following:
          </p>
          <p>
            <code>{'${r._check_name}'}</code> The name of this check
          </p>
          <p>
            <code>{'${r._level}'}</code> Indicates the level of the check
          </p>
          <p>
            <code>{'${string(v: r.numericColumn)}'}</code> Functions can be used{' '}
            as well
          </p>
          <p>
            Need help? Check out the Status Message Template{' '}
            <a
              href="https://v2.docs.influxdata.com/v2.0/monitor-alert/checks/create/#flux-only-interpolates-string-values"
              target="_blank"
            >
              Documentation
            </a>
          </p>
        </div>
      </BuilderCard.Body>
    </BuilderCard>
  )
}

const mstp = (state: AppState): StateProps => {
  const {
    alerting: {check},
  } = getActiveTimeMachine(state)

  return {check}
}

const mdtp: DispatchProps = {
  onUpdateTimeMachineCheck: updateTimeMachineCheck,
}

export default connect<StateProps, DispatchProps, {}>(
  mstp,
  mdtp
)(CheckMessageCard)
