using Microsoft.AspNetCore.Mvc.Filters;

namespace CryptoAPI.filter
{
    //фильр для передачи системы от которой пришел запрос
    public class CustomFilterAttribute : ActionFilterAttribute
    {
        private readonly string _parameterName;
        private readonly string _parameterValue;

        public CustomFilterAttribute(string parameterName, string parameterValue)
        {
            _parameterName = parameterName;
            _parameterValue = parameterValue;
        }

        public override void OnActionExecuting(ActionExecutingContext context)
        {// парсим джвт и вставляем его систему в параметр 
            context.ActionArguments[_parameterName] = _parameterValue;

            base.OnActionExecuting(context);
        }
    }
}
